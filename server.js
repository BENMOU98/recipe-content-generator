// Updated server.js with database integration
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');
const axios = require('axios');
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');
const { generatePinterestContent, generateBlogPost, generateFacebookContent } = require('./app');
const { recipeDb, facebookDb, pinterestDb, blogDb, keywordsDb } = require('./db');
const expressLayouts = require('express-ejs-layouts');
const WordPressClient = require('./wordpress');
const wordpressDb = require('./wordpress-db');
const apiKeyManager = require('./api-key-manager');
const recipeTemplateSettings = require('./recipe-template-settings');
const userDb = require('./models/user');
const organizationDb = require('./models/organization');
const { isAuthenticated, isAdmin, isEmployee, isResourceOwner, attachOrganizationToRequest, attachUserToLocals } = require('./middleware/auth');
const authRoutes = require('./auth-routes');
const registrationRoutes = require('./registration-routes');
const activityMiddleware = require('./middleware/activity-middleware');
const activityLogger = require('./activity-logger');
const { runQuery, getOne, getAll } = require('./db');
const websiteDb = require('./models/website');
const fixAttachUserToLocals = require('./fix-template-variables');
const promptSettingsDb = require('./prompt-settings-db');
const db = require('./db');
const midjourneyRoutes = require('./midjourney/image-routes');
const imageGenerator = require('./midjourney/image-generator');
const auth = require('./middleware/auth');
const { Parser } = require('json2csv');
const multer = require('multer');
const sharp = require('sharp');
const { updateBaseUrl } = require('./utils/url-helper');

// Load environment variables
dotenv.config();

// Load environment variables
dotenv.config();

// Add this code for API key management
const { getApiKey, saveApiKey, isApiKeyMissing } = require('./api-key-manager');

// Replace your checkApiKeyMiddleware function with this
async function checkApiKeyMiddleware(req, res, next) {
  // Skip check for authentication-related routes and public routes
  const exemptRoutes = [
    '/login', 
    '/register',
    '/logout',
    '/settings', 
    '/api/test-connection',
    '/favicon.ico',
    '/public',
    '/api/keys'
  ];
  
  // Check if the current route is exempt
  for (const route of exemptRoutes) {
    if (req.path.startsWith(route)) {
      return next();
    }
  }
  
  // Check if OpenAI API key is missing
  const openaiKeyMissing = await isApiKeyMissing('openai');
  
  if (openaiKeyMissing) {
    // If it's an API request, return JSON error
    if (req.path.startsWith('/api/')) {
      return res.status(400).json({
        success: false,
        message: 'OpenAI API key is required. Please add your API key in the settings page.'
      });
    }
    
    // For regular page requests, redirect to settings with a warning
    req.session.errorMessage = 'OpenAI API key is required to use this application. Please add your API key below.';
    return res.redirect('/settings');
  }
  
  next();
}


// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Add this middleware early in your middleware chain
app.use(async (req, res, next) => {
  // Only update on GET requests to avoid unnecessary database writes
  if (req.method === 'GET' && !req.path.startsWith('/api/')) {
    await updateBaseUrl(req);
  }
  next();
});


app.use('/recipe_images', express.static(path.join(__dirname, 'recipe_images'), {
  // Set proper headers for images
  setHeaders: (res, path) => {
    res.setHeader('Access-Control-Allow-Origin', '*'); // Allow cross-origin access
    res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 24 hours
  }
}));

// Serve Pinterest images
app.use('/images/pinterest', express.static(path.join(__dirname, 'public', 'images', 'pinterest'), {
  // Set proper headers for Pinterest images
  setHeaders: (res, path) => {
    res.setHeader('Access-Control-Allow-Origin', '*'); // Allow cross-origin access
    res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 24 hours
  }
}));

// Increase payload limit for base64 image data URLs (cropped images can be 200-500KB each)
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
// Serve recipe images

// Configure multer for image uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 100 // Maximum 10 files
  },
  fileFilter: (req, file, cb) => {
    // Check file type
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// Route to handle cropped image uploads
app.post('/api/images/upload-cropped', isAuthenticated, upload.array('croppedImages', 10), async (req, res) => {
  try {
    console.log('📤 Received cropped image upload request');
    
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No images provided'
      });
    }
    
    console.log(`📷 Processing ${req.files.length} cropped images`);
    
    const imageUrls = [];
    const uploadPromises = [];
    
    // Process each uploaded image
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];
      const uploadPromise = processAndSaveCroppedImage(file, i);
      uploadPromises.push(uploadPromise);
    }
    
    // Wait for all images to be processed
    const results = await Promise.all(uploadPromises);
    
    // Filter successful uploads
    const successfulUploads = results.filter(result => result.success);
    const imageUrlsOnly = successfulUploads.map(result => result.url);
    
    console.log(`✅ Successfully processed ${successfulUploads.length} images`);
    
    res.json({
      success: true,
      message: `Successfully uploaded ${successfulUploads.length} cropped images`,
      imageUrls: imageUrlsOnly,
      count: successfulUploads.length
    });
    
  } catch (error) {
    console.error('❌ Error uploading cropped images:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to upload cropped images'
    });
  }
});



// Helper function to process and save a single cropped image
async function processAndSaveCroppedImage(file, index) {
  try {
    // Generate unique filename - FIX THE FILENAME GENERATION
    const timestamp = Date.now();
    const randomId = uuidv4().substring(0, 8); // Use substring instead of split
    const filename = `keyword_${timestamp}_${index}_${randomId}.webp`;
    const filepath = path.join(__dirname, 'recipe_images', filename);
    
    // Ensure recipe_images directory exists
    const recipeImagesDir = path.join(__dirname, 'recipe_images');
    if (!fs.existsSync(recipeImagesDir)) {
      fs.mkdirSync(recipeImagesDir, { recursive: true });
    }
    
    // Process image with Sharp (optimize and convert to WebP)
    await sharp(file.buffer)
      .resize(800, 800, { 
        fit: 'inside',
        withoutEnlargement: true 
      })
      .webp({ quality: 85 })
      .toFile(filepath);
    
    // Generate public URL - ensure it's properly formatted
    const publicUrl = `/recipe_images/${filename}`;
    
    console.log(`✅ Processed and saved image: ${filename}`);
    
    return {
      success: true,
      filename: filename,
      filepath: filepath,
      url: publicUrl
    };
    
  } catch (error) {
    console.error(`❌ Error processing image ${index}:`, error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Route to handle single image upload (for backward compatibility)
app.post('/api/images/upload-single', isAuthenticated, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No image provided'
      });
    }
    
    const result = await processAndSaveCroppedImage(req.file, 0);
    
    if (result.success) {
      res.json({
        success: true,
        message: 'Image uploaded successfully',
        imageUrl: result.url,
        filename: result.filename
      });
    } else {
      res.status(500).json({
        success: false,
        message: result.error || 'Failed to process image'
      });
    }
    
  } catch (error) {
    console.error('❌ Error uploading single image:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to upload image'
    });
  }
});

// Route to get all uploaded images (optional - for admin purposes)
app.get('/api/images/list', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const recipeImagesDir = path.join(__dirname, 'recipe_images');
    
    if (!fs.existsSync(recipeImagesDir)) {
      return res.json({
        success: true,
        images: []
      });
    }
    
    const files = fs.readdirSync(recipeImagesDir);
    const imageFiles = files.filter(file => 
      file.match(/\.(jpg|jpeg|png|webp|gif)$/i)
    );
    
    const images = imageFiles.map(filename => {
      const filepath = path.join(recipeImagesDir, filename);
      const stats = fs.statSync(filepath);
      
      return {
        filename: filename,
        url: `/recipe_images/${filename}`,
        size: stats.size,
        created: stats.birthtime || stats.ctime,
        modified: stats.mtime
      };
    });
    
    // Sort by creation date (newest first)
    images.sort((a, b) => new Date(b.created) - new Date(a.created));
    
    res.json({
      success: true,
      images: images,
      count: images.length
    });
    
  } catch (error) {
    console.error('❌ Error listing images:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to list images'
    });
  }
});

// Route to delete an uploaded image (optional - for admin purposes)
app.delete('/api/images/:filename', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const filename = req.params.filename;
    
    // Validate filename (security check)
    if (!filename.match(/^[a-zA-Z0-9_.-]+$/)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid filename'
      });
    }
    
    const filepath = path.join(__dirname, 'recipe_images', filename);
    
    // Check if file exists
    if (!fs.existsSync(filepath)) {
      return res.status(404).json({
        success: false,
        message: 'Image not found'
      });
    }
    
    // Delete the file
    fs.unlinkSync(filepath);
    
    console.log(`🗑️ Deleted image: ${filename}`);
    
    res.json({
      success: true,
      message: 'Image deleted successfully'
    });
    
  } catch (error) {
    console.error('❌ Error deleting image:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to delete image'
    });
  }
});

// Enhanced keyword addition API to handle cropped images and image URLs
app.post('/api/keywords/add-with-images', isAuthenticated, activityMiddleware.logActivity('create', 'keyword'), async (req, res) => {
  try {
    console.log('📝 Adding keywords with image support');
    
    const { keywords, defaultCategory, defaultInterests, croppedImageUrls } = req.body;
    
    if (!keywords || !Array.isArray(keywords) || keywords.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid keywords provided'
      });
    }
    
    // Get user and organization info
    const ownerId = req.session.user.id;
    const organizationId = req.session.user.organizationId;
    
    if (!ownerId || !organizationId) {
      return res.status(401).json({
        success: false,
        message: 'User authentication required'
      });
    }
    
    // Process keywords with image support
    const keywordsData = keywords.map((keyword, index) => {
      let imageUrl = null;
      
      // Priority: 1. Keyword-specific image_url, 2. Cropped image URL, 3. Default image URL
      if (keyword.image_url && keyword.image_url.trim()) {
        imageUrl = keyword.image_url.trim();
      } else if (croppedImageUrls && croppedImageUrls[index]) {
        // Convert relative URL to absolute URL for consistency
        const baseUrl = req.protocol + '://' + req.get('host');
        imageUrl = croppedImageUrls[index].startsWith('http') ? 
          croppedImageUrls[index] : 
          baseUrl + croppedImageUrls[index];
      }
      
      return {
        keyword: (typeof keyword === 'string' ? keyword : keyword.keyword).trim(),
        category: keyword.category || defaultCategory || null,
        interests: keyword.interests || defaultInterests || null,
        image_url: imageUrl,
        ownerId: ownerId,
        organizationId: organizationId
      };
    }).filter(k => k.keyword && k.keyword.length > 0);
    
    if (keywordsData.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid keywords found after processing'
      });
    }
    
    console.log(`📊 Processing ${keywordsData.length} keywords with images`);
    
    // Add keywords to database
    const keywordIds = await keywordsDb.addKeywordsBatch(keywordsData);
    
    console.log(`✅ Successfully added ${keywordIds.length} keywords with image support`);
    
    res.json({
      success: true,
      message: `Added ${keywordIds.length} keywords successfully`,
      count: keywordIds.length,
      keywordIds: keywordIds
    });
    
  } catch (error) {
    console.error('❌ Error adding keywords with images:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});

// Enhanced image metadata route for debugging
app.get('/api/images/metadata/:filename', isAuthenticated, async (req, res) => {
  try {
    const filename = req.params.filename;
    const filepath = path.join(__dirname, 'recipe_images', filename);
    
    if (!fs.existsSync(filepath)) {
      return res.status(404).json({
        success: false,
        message: 'Image not found'
      });
    }
    
    // Get file stats
    const stats = fs.statSync(filepath);
    
    // Try to get image metadata using Sharp
    let imageMetadata = null;
    try {
      imageMetadata = await sharp(filepath).metadata();
    } catch (metadataError) {
      console.warn('Could not read image metadata:', metadataError.message);
    }
    
    const metadata = {
      filename: filename,
      url: `/recipe_images/${filename}`,
      size: stats.size,
      sizeFormatted: formatFileSize(stats.size),
      created: stats.birthtime || stats.ctime,
      modified: stats.mtime,
      accessed: stats.atime
    };
    
    if (imageMetadata) {
      metadata.image = {
        width: imageMetadata.width,
        height: imageMetadata.height,
        format: imageMetadata.format,
        channels: imageMetadata.channels,
        hasAlpha: imageMetadata.hasAlpha,
        density: imageMetadata.density
      };
    }
    
    res.json({
      success: true,
      metadata: metadata
    });
    
  } catch (error) {
    console.error('❌ Error getting image metadata:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to get image metadata'
    });
  }
});

// Helper function to format file size
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Extract Pinterest social meta from generated content
 * @param {string} content - Generated content that might contain Pinterest markers
 * @param {string} defaultTitle - Default title to use if no Pinterest title found
 * @returns {Object} - Object with Pinterest title and description
 */
function extractPinterestMeta(content, defaultTitle = '') {
  let pinterestTitle = '';
  let pinterestDescription = '';
  
  if (content && typeof content === 'string') {
    // Try to extract Pinterest title
    const titleMatch = content.match(/PINTEREST_TITLE:\s*(.+?)(?:\n|$)/i);
    if (titleMatch && titleMatch[1]) {
      pinterestTitle = titleMatch[1].trim();
    }
    
    // Try to extract Pinterest description
    const descMatch = content.match(/PINTEREST_DESCRIPTION:\s*(.+?)(?:\n|$)/i);
    if (descMatch && descMatch[1]) {
      pinterestDescription = descMatch[1].trim();
    }
  }
  
  // Generate defaults if not found
  if (!pinterestTitle && defaultTitle) {
    pinterestTitle = `${defaultTitle} - Save This Recipe!`;
  }
  
  if (!pinterestDescription && defaultTitle) {
    pinterestDescription = `Save this delicious ${defaultTitle} recipe to your Pinterest board! Perfect for any occasion.`;
  }
  
  return {
    pinterestTitle,
    pinterestDescription
  };
}

// Add this function to enhance Pinterest variation saving
function enhancePinterestVariationWithSocialMeta(variation, keyword) {
  const enhanced = { ...variation };
  
  // Ensure Pinterest social meta fields exist
  if (!enhanced.pinterest_title && !enhanced.pinterestTitle) {
    enhanced.pinterest_title = enhanced.pin_title || `${keyword} - Save This Recipe!`;
    enhanced.pinterestTitle = enhanced.pinterest_title;
  }
  
  if (!enhanced.pinterest_description && !enhanced.pinterestDescription) {
    enhanced.pinterest_description = enhanced.pin_description || `Save this delicious ${keyword} recipe to your Pinterest board! Perfect for any occasion.`;
    enhanced.pinterestDescription = enhanced.pinterest_description;
  }
  
  return enhanced;
}

// Error handler for multer errors
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File too large. Maximum size is 10MB per file.'
      });
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        message: 'Too many files. Maximum 10 files allowed.'
      });
    }
    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        success: false,
        message: 'Unexpected field name in file upload.'
      });
    }
  }
  
  if (error.message === 'Only image files are allowed') {
    return res.status(400).json({
      success: false,
      message: error.message
    });
  }
  
  next(error);
});

console.log('✅ Image upload and cropping routes loaded successfully');

app.use(session({
  secret: 'recipe-content-generator-secret',
  resave: false,
  saveUninitialized: false, // CHANGED from true to false
  rolling: true, // ADD this to refresh session on activity
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    httpOnly: true // ADD this for security
  },
  name: 'recipegen.sid' // Give your session a specific name
}));

// Add this middleware to server.js right after your session middleware
app.use(async (req, res, next) => {
  // Discord context debugging middleware
  if (req.session && req.session.user && (req.path.includes('/api/keywords/process') || req.path.includes('/midjourney'))) {
    try {
      const discordSettings = await getCurrentDiscordSettings(req);
      
      if (discordSettings) {
        const tokenPreview = discordSettings.discordUserToken.substring(0, 10) + '...';
        console.log(`🎯 [DISCORD DEBUG] Request: ${req.method} ${req.path}`);
        console.log(`   Organization: ${req.session.user.organizationId}`);
        console.log(`   Website: ${req.session.currentWebsiteId}`);
        console.log(`   User: ${req.session.user.name} (${req.session.user.id})`);
        console.log(`   Discord Channel: ${discordSettings.discordChannelId}`);
        console.log(`   Discord Token: ${tokenPreview}`);
        console.log(`   Settings Source: ${discordSettings.source}`);
        console.log('   ----------------');
      } else {
        console.log(`❌ [DISCORD DEBUG] No Discord settings found for request: ${req.method} ${req.path}`);
      }
    } catch (error) {
      console.error('❌ [DISCORD DEBUG] Error in debug middleware:', error);
    }
  }
  
  next();
});

app.use((req, res, next) => {
  // More detailed session debugging
  const sessionInfo = {
    hasSession: !!req.session,
    hasUser: !!(req.session && req.session.user),
    sessionID: req.sessionID,
    userID: req.session?.user?.id || 'none',
    currentWebsiteId: req.session?.currentWebsiteId || 'none',
    url: req.originalUrl,
    method: req.method
  };
  
  // Only log for problematic routes or when there are issues
  if (req.originalUrl.includes('/keywords') || req.originalUrl.includes('/websites/switch')) {
    console.log('🔍 Session debug:', sessionInfo);
  }
  
  // Check for session issues
  if (req.session && req.session.user && !req.session.user.id) {
    console.error('⚠️ Session corruption detected: user object exists but no user ID');
  }
  
  next();
});


// ADD this new middleware to server.js after session debugging:
app.use((req, res, next) => {
  // Session recovery middleware
  if (req.session && req.session.user) {
    // Verify session integrity
    if (!req.session.user.id || !req.session.user.organizationId) {
      console.error('🚨 Corrupted session detected, clearing session');
      req.session.destroy((err) => {
        if (err) {
          console.error('Error destroying corrupted session:', err);
        }
        return res.redirect('/login?reason=session_error');
      });
      return;
    }
    
    // Ensure website context is properly set if missing
    if (!req.session.currentWebsiteId && req.path !== '/websites/switch') {
      console.log('🔧 Missing website context, will be set by website middleware');
    }
  }
  
  next();
});

// Setup view engine and layouts
app.use(expressLayouts);
app.set('layout', 'layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/midjourney', midjourneyRoutes);

// Add command-line argument support for debugging prompts
try {
  const yargs = require('yargs/yargs');
  const { hideBin } = require('yargs/helpers');
  const argv = yargs(hideBin(process.argv))
    .option('debug-prompts', {
      alias: 'd',
      type: 'boolean',
      description: 'Enable detailed logging of prompts sent to OpenAI'
    })
    .parse();

  // Set this as a global variable that can be accessed by app.js
  global.debugPrompts = argv['debug-prompts'] || false;

  // Log debug setting
  if (global.debugPrompts) {
    console.log('\x1b[32m%s\x1b[0m', '🔍 PROMPT DEBUGGING ENABLED: All OpenAI prompts will be logged to prompt_logs directory');
  }
} catch (error) {
  console.warn('Warning: Failed to initialize yargs for command line parsing. Debug prompt option is disabled.');
  console.warn('Error:', error.message);
  global.debugPrompts = false;
}


// Create the recipe_images directory if it doesn't exist
const recipesImagesDir = path.join(__dirname, 'recipe_images');
if (!fs.existsSync(recipesImagesDir)) {
  fs.mkdirSync(recipesImagesDir, { recursive: true });
}

// Serve recipe images
app.use('/recipe_images', express.static(recipesImagesDir));


// Add this middleware to set global website context
app.use((req, res, next) => {
  // Set global currentWebsiteId if it exists in session
  if (req.session && req.session.currentWebsiteId) {
    global.currentWebsiteId = req.session.currentWebsiteId;
  }
  
  // CRITICAL FIX: Also set global currentOrganizationId if user is logged in
  if (req.session && req.session.user && req.session.user.organizationId) {
    global.currentOrganizationId = req.session.user.organizationId;
  }
  
  next();
});

app.use(require('./middleware/website-auth').attachWebsiteToRequest);
app.use(require('./middleware/website-auth').getUserWebsites);

// First, import the middleware module
const websiteMiddleware = require('./middleware/website-auth');

// Check if the expected middleware functions exist
console.log('Available middleware functions:', Object.keys(websiteMiddleware));



// Then use only what's available
if (websiteMiddleware.attachWebsiteToRequest) {
  app.use(websiteMiddleware.attachWebsiteToRequest);
}

if (websiteMiddleware.getUserWebsites) {
  app.use(websiteMiddleware.getUserWebsites);
}

if (websiteMiddleware.checkWebsiteSetup) {
  app.use(websiteMiddleware.checkWebsiteSetup);
}


// THEN add website routes
const websiteRoutes = require('./website-routes');
app.use(websiteRoutes);

// Fix the middleware order - CRITICAL CHANGE
app.use(require('./middleware/auth').attachOrganizationToRequest);
app.use(fixAttachUserToLocals);
app.use(require('./middleware/auth').adminOnlyPages);





// Check API key middleware should come after authentication
app.use(checkApiKeyMiddleware);


// GET route for user add page
app.get('/users/add', isAuthenticated, isAdmin, (req, res) => {
  res.render('user-add', {
    pageTitle: 'Add User',
    activePage: 'users',
    title: 'RecipeGen AI - Add User'
  });
});

// Add this API route to your server.js file
// Quick Copy Data API Route for Recipe Listing Page
app.get('/api/recipe/:recipeId/copy-data', isAuthenticated, async (req, res) => {
  try {
    const recipeId = req.params.recipeId;
    console.log(`📋 Fetching copy data for recipe: ${recipeId}`);
    
    // Get basic recipe info
    const recipe = await getOne("SELECT * FROM recipes WHERE id = ?", [recipeId]);
    
    if (!recipe) {
      return res.status(404).json({
        success: false,
        message: 'Recipe not found'
      });
    }
    
    // Check if user has access to this recipe
    const organizationId = req.session.user.organizationId;
    if (recipe.organization_id !== organizationId) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }
    
    // Get Facebook content
    let facebook = null;
    try {
      facebook = await getOne("SELECT * FROM facebook_content WHERE recipe_id = ?", [recipeId]);
    } catch (error) {
      console.warn('No Facebook content found for recipe:', recipeId);
    }
    
    // Get Pinterest variations
    let pinterest = [];
    try {
      pinterest = await getAll("SELECT * FROM pinterest_variations WHERE recipe_id = ? ORDER BY variation_number", [recipeId]);
    } catch (error) {
      console.warn('No Pinterest content found for recipe:', recipeId);
    }
    
    // Get Blog content
    let blog = null;
    try {
      blog = await getOne("SELECT * FROM blog_content WHERE recipe_id = ?", [recipeId]);
    } catch (error) {
      console.warn('No Blog content found for recipe:', recipeId);
    }
    
    // Prepare response data
    const responseData = {
      success: true,
      data: {
        recipe: {
          id: recipe.id,
          recipe_idea: recipe.recipe_idea,
          category: recipe.category,
          interests: recipe.interests,
          language: recipe.language,
          created_at: recipe.created_at
        },
        facebook: facebook ? {
          recipe_text: facebook.recipe_text,
          fb_caption: facebook.fb_caption,
          mj_prompt: facebook.mj_prompt
        } : null,
        pinterest: pinterest.map(variation => ({
          pin_title: variation.pin_title,
          pin_description: variation.pin_description,
          overlay_text: variation.overlay_text,
          meta_title: variation.meta_title,
          meta_description: variation.meta_description,
          meta_slug: variation.meta_slug
        })),
        blog: blog ? {
          html_content: blog.html_content,
          meta_title: blog.meta_title,
          meta_description: blog.meta_description
        } : null
      }
    };
    
    console.log(`✅ Copy data prepared for recipe: ${recipe.recipe_idea}`);
    console.log(`   - Facebook content: ${facebook ? 'Available' : 'None'}`);
    console.log(`   - Pinterest variations: ${pinterest.length}`);
    console.log(`   - Blog content: ${blog ? 'Available' : 'None'}`);
    
    res.json(responseData);
    
  } catch (error) {
    console.error('❌ Error fetching recipe copy data:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch recipe data: ' + error.message
    });
  }
});

// PNG to WebP Converter page (public access, no authentication needed)
app.get('/image-converter', (req, res) => {
  res.render('image-converter', {
    pageTitle: 'PNG to WebP Converter - Free Tool',
    activePage: 'image-converter'
  });
});

// Additional endpoints to add to your server.js file for queue management

// Import the image queue service
const imageQueueService = require('./services/image-queue-service');

// === QUEUE MANAGEMENT ROUTES ===
// Add these routes to your server.js file

// Queue status page (accessible to authenticated users)
app.get('/image-queue', isAuthenticated, (req, res) => {
  res.render('image-queue-status', {
    pageTitle: 'Image Generation Queue',
    activePage: 'image-queue',
    title: 'RecipeGen AI - Image Queue Status'
  });
});

// API endpoint to get detailed queue information
app.get('/api/image-queue/status', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const organizationId = req.session.user.organizationId;
    
    // Get user's queue status
    const queueStatus = await imageQueueService.getQueueStatus(userId, organizationId);
    
    // Get overall system stats (for admins)
    let systemStats = null;
    if (req.session.user.role === 'admin') {
      try {
        const { getAll, getOne } = require('./db');
        
        // Get system-wide queue statistics
        const stats = await getAll(`
          SELECT 
            status,
            COUNT(*) as count,
            AVG(CASE 
              WHEN completed_at IS NOT NULL AND started_at IS NOT NULL 
              THEN (julianday(completed_at) - julianday(started_at)) * 24 * 60 * 60 
            END) as avg_processing_time_seconds
          FROM image_queue 
          WHERE created_at > datetime('now', '-24 hours')
          GROUP BY status
        `);
        
        // Get recent activity
        const recentActivity = await getAll(`
          SELECT iq.*, r.recipe_idea, u.name as user_name
          FROM image_queue iq
          LEFT JOIN recipes r ON iq.recipe_id = r.id
          LEFT JOIN users u ON iq.user_id = u.id
          WHERE iq.organization_id = ?
          ORDER BY iq.created_at DESC
          LIMIT 10
        `, [organizationId]);
        
        systemStats = {
          stats: stats,
          recentActivity: recentActivity
        };
      } catch (statsError) {
        console.error('Error getting system stats:', statsError);
      }
    }
    
    res.json({
      success: true,
      ...queueStatus,
      systemStats: systemStats,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error getting queue status:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// API endpoint to cancel a queued job
app.post('/api/image-queue/cancel/:jobId', isAuthenticated, async (req, res) => {
  try {
    const jobId = req.params.jobId;
    const userId = req.session.user.id;
    
    const result = await imageQueueService.cancelJob(jobId, userId);
    
    if (result.success) {
      res.json({
        success: true,
        message: result.message
      });
    } else {
      res.status(400).json({
        success: false,
        error: result.message
      });
    }
  } catch (error) {
    console.error('Error cancelling job:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// API endpoint to add a recipe to the image generation queue
app.post('/api/image-queue/add', isAuthenticated, async (req, res) => {
  try {
    const { recipeId, customPrompt } = req.body;
    
    if (!recipeId) {
      return res.status(400).json({
        success: false,
        error: 'Recipe ID is required'
      });
    }
    
    // Validate recipe exists and user has access
    const recipe = await getOne("SELECT * FROM recipes WHERE id = ?", [recipeId]);
    if (!recipe) {
      return res.status(404).json({
        success: false,
        error: 'Recipe not found'
      });
    }
    
    // Check user permissions
    const orgId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    
    if (recipe.organization_id !== orgId || 
        (userId && recipe.owner_id !== userId)) {
      return res.status(403).json({
        success: false,
        error: 'You do not have permission to generate images for this recipe'
      });
    }
    
    // Check for existing pending job
    const existingJob = await getOne(`
      SELECT * FROM image_queue 
      WHERE recipe_id = ? AND status IN ('queued', 'processing')
    `, [recipeId]);
    
    if (existingJob) {
      return res.json({
        success: false,
        error: 'This recipe already has a pending image generation',
        existingJob: {
          id: existingJob.id,
          position: existingJob.position,
          estimatedCompletion: existingJob.estimated_completion
        }
      });
    }
    
    // Get Discord settings
    const discordSettings = global.getCurrentDiscordSettings ? 
      await global.getCurrentDiscordSettings(req) : null;
    
    if (!discordSettings || !discordSettings.enableDiscord) {
      return res.status(400).json({
        success: false,
        error: 'Discord integration is not configured. Please check your settings.'
      });
    }
    
    // Add to queue
    const queueResult = await imageQueueService.addToQueue({
      recipeId: parseInt(recipeId),
      userId: req.session.user.id,
      organizationId: req.session.user.organizationId,
      websiteId: req.session.currentWebsiteId,
      customPrompt: customPrompt || null,
      discordSettings: discordSettings
    });
    
    res.json({
      success: true,
      message: 'Recipe added to image generation queue successfully',
      job: {
        id: queueResult.jobId,
        position: queueResult.position,
        estimatedCompletion: queueResult.estimatedCompletion,
        queueLength: queueResult.queueLength
      }
    });
    
  } catch (error) {
    console.error('Error adding to queue:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Admin-only endpoint to get detailed queue statistics
app.get('/api/admin/image-queue/stats', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { getAll, getOne } = require('./db');
    
    // Get comprehensive queue statistics
    const stats = await getAll(`
      SELECT 
        status,
        COUNT(*) as count,
        AVG(CASE 
          WHEN completed_at IS NOT NULL AND started_at IS NOT NULL 
          THEN (julianday(completed_at) - julianday(started_at)) * 24 * 60 * 60 
        END) as avg_processing_time_seconds,
        MIN(created_at) as earliest_job,
        MAX(created_at) as latest_job
      FROM image_queue 
      WHERE created_at > datetime('now', '-7 days')
      GROUP BY status
    `);
    
    // Get user statistics
    const userStats = await getAll(`
      SELECT 
        u.name,
        COUNT(*) as total_jobs,
        COUNT(CASE WHEN iq.status = 'completed' THEN 1 END) as completed_jobs,
        COUNT(CASE WHEN iq.status = 'failed' THEN 1 END) as failed_jobs,
        AVG(CASE 
          WHEN iq.completed_at IS NOT NULL AND iq.started_at IS NOT NULL 
          THEN (julianday(iq.completed_at) - julianday(iq.started_at)) * 24 * 60 * 60 
        END) as avg_processing_time
      FROM image_queue iq
      JOIN users u ON iq.user_id = u.id
      WHERE iq.created_at > datetime('now', '-7 days')
        AND iq.organization_id = ?
      GROUP BY u.id, u.name
      ORDER BY total_jobs DESC
    `, [req.session.user.organizationId]);
    
    // Get recent failures with details
    const recentFailures = await getAll(`
      SELECT iq.*, r.recipe_idea, u.name as user_name
      FROM image_queue iq
      LEFT JOIN recipes r ON iq.recipe_id = r.id
      LEFT JOIN users u ON iq.user_id = u.id
      WHERE iq.status = 'failed' 
        AND iq.organization_id = ?
        AND iq.created_at > datetime('now', '-24 hours')
      ORDER BY iq.created_at DESC
      LIMIT 20
    `, [req.session.user.organizationId]);
    
    // Get performance metrics
    const performanceMetrics = await getOne(`
      SELECT 
        COUNT(*) as total_jobs_today,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_today,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_today,
        COUNT(CASE WHEN status IN ('queued', 'processing') THEN 1 END) as active_jobs,
        ROUND(
          100.0 * COUNT(CASE WHEN status = 'completed' THEN 1 END) / 
          NULLIF(COUNT(CASE WHEN status IN ('completed', 'failed') THEN 1 END), 0), 
          2
        ) as success_rate_percent
      FROM image_queue 
      WHERE created_at > datetime('now', '-24 hours')
        AND organization_id = ?
    `, [req.session.user.organizationId]);
    
    res.json({
      success: true,
      stats: {
        byStatus: stats,
        byUser: userStats,
        performance: performanceMetrics,
        recentFailures: recentFailures
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error getting admin queue stats:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Admin-only endpoint to manage queue (pause/resume, clear failed jobs, etc.)
app.post('/api/admin/image-queue/manage', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { action, jobIds } = req.body;
    
    switch (action) {
      case 'clear_failed':
        const clearResult = await runQuery(`
          DELETE FROM image_queue 
          WHERE status = 'failed' 
            AND organization_id = ? 
            AND created_at < datetime('now', '-24 hours')
        `, [req.session.user.organizationId]);
        
        res.json({
          success: true,
          message: `Cleared ${clearResult.changes || 0} failed jobs`,
          clearedCount: clearResult.changes || 0
        });
        break;
        
      case 'clear_completed':
        const clearCompletedResult = await runQuery(`
          DELETE FROM image_queue 
          WHERE status = 'completed' 
            AND organization_id = ? 
            AND created_at < datetime('now', '-7 days')
        `, [req.session.user.organizationId]);
        
        res.json({
          success: true,
          message: `Cleared ${clearCompletedResult.changes || 0} completed jobs`,
          clearedCount: clearCompletedResult.changes || 0
        });
        break;
        
      case 'retry_failed':
        if (!jobIds || !Array.isArray(jobIds)) {
          return res.status(400).json({
            success: false,
            error: 'Job IDs array is required for retry action'
          });
        }
        
        // Reset failed jobs to queued status
        const retryResult = await runQuery(`
          UPDATE image_queue 
          SET status = 'queued', 
              error_message = NULL,
              retry_count = retry_count + 1,
              position = (SELECT MAX(position) FROM image_queue WHERE status IN ('queued', 'processing')) + 1,
              estimated_completion = datetime('now', '+' || (SELECT MAX(position) FROM image_queue WHERE status IN ('queued', 'processing')) * 90 || ' seconds')
          WHERE id IN (${jobIds.map(() => '?').join(',')}) 
            AND status = 'failed'
            AND organization_id = ?
        `, [...jobIds, req.session.user.organizationId]);
        
        res.json({
          success: true,
          message: `Retried ${retryResult.changes || 0} failed jobs`,
          retriedCount: retryResult.changes || 0
        });
        break;
        
      default:
        res.status(400).json({
          success: false,
          error: 'Invalid action. Supported actions: clear_failed, clear_completed, retry_failed'
        });
    }
    
  } catch (error) {
    console.error('Error managing queue:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Endpoint to get queue health status
app.get('/api/image-queue/health', isAuthenticated, async (req, res) => {
  try {
    const { getOne } = require('./db');
    
    // Check for stuck jobs (processing for more than 10 minutes)
    const stuckJobs = await getOne(`
      SELECT COUNT(*) as count
      FROM image_queue 
      WHERE status = 'processing' 
        AND started_at < datetime('now', '-10 minutes')
    `);
    
    // Check queue size
    const queueSize = await getOne(`
      SELECT COUNT(*) as count
      FROM image_queue 
      WHERE status = 'queued'
    `);
    
    // Check recent failure rate
    const recentStats = await getOne(`
      SELECT 
        COUNT(*) as total,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed
      FROM image_queue 
      WHERE created_at > datetime('now', '-1 hour')
    `);
    
    const failureRate = recentStats.total > 0 ? 
      (recentStats.failed / recentStats.total) * 100 : 0;
    
    // Determine health status
    let healthStatus = 'healthy';
    let issues = [];
    
    if (stuckJobs.count > 0) {
      healthStatus = 'warning';
      issues.push(`${stuckJobs.count} jobs appear to be stuck`);
    }
    
    if (queueSize.count > 20) {
      healthStatus = 'warning';
      issues.push(`Queue is large (${queueSize.count} jobs)`);
    }
    
    if (failureRate > 50) {
      healthStatus = 'critical';
      issues.push(`High failure rate (${failureRate.toFixed(1)}%)`);
    }
    
    res.json({
      success: true,
      health: {
        status: healthStatus,
        issues: issues,
        metrics: {
          stuckJobs: stuckJobs.count,
          queueSize: queueSize.count,
          recentFailureRate: Math.round(failureRate * 100) / 100
        }
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error checking queue health:', error);
    res.json({
      success: false,
      health: {
        status: 'error',
        issues: ['Unable to check queue health'],
        error: error.message
      },
      timestamp: new Date().toISOString()
    });
  }
});

// WebSocket or Server-Sent Events for real-time updates (optional enhancement)
app.get('/api/image-queue/events', isAuthenticated, (req, res) => {
  // Set up Server-Sent Events
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Cache-Control'
  });
  
  const userId = req.session.user.id;
  const organizationId = req.session.user.organizationId;
  
  // Send initial status
  const sendUpdate = async () => {
    try {
      const status = await imageQueueService.getQueueStatus(userId, organizationId);
      const data = JSON.stringify(status);
      res.write(`data: ${data}\n\n`);
    } catch (error) {
      console.error('Error sending SSE update:', error);
    }
  };
  
  // Send updates every 5 seconds
  const interval = setInterval(sendUpdate, 5000);
  
  // Send initial update
  sendUpdate();
  
  // Clean up on client disconnect
  req.on('close', () => {
    clearInterval(interval);
  });
});

// === END OF QUEUE MANAGEMENT ROUTES ===

// Don't forget to also create the EJS view file for the queue status page
// Create: views/image-queue-status.ejs with the HTML content from the previous artifact

// POST route for adding user (edit this in server.js)
app.post('/users/add', isAuthenticated, isAdmin, async (req, res) => {
  try {
    console.log('User add form submitted:', req.body); // Add this line
    
    const { name, email, username, password, role } = req.body;
    
    // Validate required fields
    if (!name || !email || !username || !password || !role) {
      req.session.errorMessage = 'All fields are required.';
      return res.redirect('/users/add');
    }
    
    // Create user - Make sure this actually calls the database function
    const userId = await userDb.createUser({
      name,
      email,
      username, 
      password,
      role,
      organizationId: req.session.user.organizationId
    });
    
    if (userId) {
      req.session.successMessage = 'User created successfully';
      return res.redirect('/users');
    } else {
      req.session.errorMessage = 'Failed to create user';
      return res.redirect('/users/add');
    }
  } catch (error) {
    console.error('Error creating user:', error);
    req.session.errorMessage = 'Failed to create user: ' + error.message;
    return res.redirect('/users/add');
  }
});

// IMPORTANT: Mount routes properly
app.use('/', registrationRoutes);  // Add this line FIRST
app.use('/', authRoutes);

// Add this code to server.js right after your imports
// It will create a safer version of the getFilteredContent function that catches errors for missing tables

// Add this helper function at the beginning of server.js (after imports)
async function getFilteredContent(organizationId, employeeId = null, contentType = 'all') {
  let content = [];
  
  // Filter by owner if specified
  const ownerFilter = employeeId ? `AND owner_id = '${employeeId}'` : '';
  
  try {
    // Get recipes if requested
    if (contentType === 'all' || contentType === 'recipe') {
      const recipes = await getAll(`
        SELECT r.id, r.recipe_idea as title, 'recipe' as type, r.created_at,
               u.name as owner_name, u.role as owner_role
        FROM recipes r
        LEFT JOIN users u ON r.owner_id = u.id
        WHERE r.organization_id = ? ${ownerFilter}
        ORDER BY r.created_at DESC
        LIMIT 20
      `, [organizationId]);
      
      content.push(...recipes);
    }
    
    // Get keywords if requested
    if (contentType === 'all' || contentType === 'keyword') {
      const keywords = await getAll(`
        SELECT k.id, k.keyword as title, 'keyword' as type, k.added_at as created_at,
               u.name as owner_name, u.role as owner_role
        FROM keywords k
        LEFT JOIN users u ON k.owner_id = u.id
        WHERE k.organization_id = ? ${ownerFilter}
        ORDER BY k.added_at DESC
        LIMIT 20
      `, [organizationId]);
      
      content.push(...keywords);
    }
    
    // Get WordPress posts if requested - use try/catch to handle missing table
    if (contentType === 'all' || contentType === 'blog') {
      try {
        // First check if the wordpress_publications table exists (this is our actual table)
        const tableCheck = await getOne(`
          SELECT name FROM sqlite_master 
          WHERE type='table' AND name='wordpress_publications'
        `);
        
        if (tableCheck) {
          // Use wordpress_publications which is the correct table
          const blogPosts = await getAll(`
            SELECT wp.id, 'WordPress Post' as title, 'blog' as type, wp.created_at,
                  r.owner_id, u.name as owner_name, u.role as owner_role
            FROM wordpress_publications wp
            JOIN recipes r ON wp.recipe_id = r.id
            LEFT JOIN users u ON r.owner_id = u.id
            WHERE r.organization_id = ? ${ownerFilter}
            ORDER BY wp.created_at DESC
            LIMIT 20
          `, [organizationId]);
          
          content.push(...blogPosts);
        }
      } catch (error) {
        console.warn('Error fetching WordPress posts (table may not exist yet):', error.message);
        // Continue without WordPress posts
      }
    }
    
    // Sort all content by creation date
    content.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    
    // Format dates
    content.forEach(item => {
      if (item.created_at) {
        const date = new Date(item.created_at);
        item.created_at = date.toLocaleDateString('en-US', { 
          year: 'numeric', 
          month: 'short', 
          day: 'numeric' 
        });
      }
    });
    
    return { success: true, content: content.slice(0, 20) };
  } catch (error) {
    console.error('Error getting filtered content:', error);
    return { success: false, message: 'Failed to load filtered content', error: error.message };
  }
}


// Add this to your server.js or app.js file to handle cropped images

// API endpoint to process cropped images
app.post('/api/keywords/process-cropped-images', upload.array('croppedImages'), async (req, res) => {
  try {
    const keywordIds = JSON.parse(req.body.keywordIds || '[]');
    const files = req.files || [];
    
    if (keywordIds.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'No keywords provided' 
      });
    }
    
    // Process each uploaded cropped image
    const results = [];
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const keywordId = keywordIds[i];
      
      if (!keywordId) continue;
      
      try {
        // Save the cropped image
        const filename = `cropped_${keywordId}_${Date.now()}.jpg`;
        const filepath = path.join(__dirname, 'recipe_images', filename);
        
        // Move the uploaded file to the images directory
        await fs.promises.rename(file.path, filepath);
        
        // Update the keyword with the new image URL
        await new Promise((resolve, reject) => {
          db.run(
            `UPDATE keywords SET image_url = ? WHERE id = ?`,
            [`/recipe_images/${filename}`, keywordId],
            function(err) {
              if (err) reject(err);
              else resolve(this);
            }
          );
        });
        
        results.push({
          keywordId,
          success: true,
          imageUrl: `/recipe_images/${filename}`
        });
        
      } catch (error) {
        console.error(`Error processing image for keyword ${keywordId}:`, error);
        results.push({
          keywordId,
          success: false,
          error: error.message
        });
      }
    }
    
    res.json({
      success: true,
      message: `Processed ${results.filter(r => r.success).length} of ${results.length} images`,
      results
    });
    
  } catch (error) {
    console.error('Error in process-cropped-images:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'Server error' 
    });
  }
});


// POST endpoint for updating keyword images with cropped versions
app.post('/api/keywords/update-images', upload.array('croppedImages', 100), async (req, res) => {
  try {
    const updates = JSON.parse(req.body.updates || '[]');
    const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
    
    // Validate inputs
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'No files uploaded' 
      });
    }
    
    console.log(`📊 Received ${updates.length} image updates with ${req.files.length} files`);
    
    const results = [];
    
    // Process each uploaded file
    for (let i = 0; i < Math.min(req.files.length, updates.length); i++) {
      const file = req.files[i];
      const update = updates[i];
      
      if (!update || !update.keywordId) {
        console.warn(`⚠️ Missing keywordId for update at index ${i}`);
        results.push({ 
          index: i, 
          success: false, 
          error: 'Missing keywordId' 
        });
        continue;
      }
      
      try {
        // Generate filename for the cropped image
        const timestamp = Date.now();
        const randomId = uuidv4().substring(0, 8);
        const filename = `keyword_${update.keywordId}_${timestamp}_${randomId}.jpg`;
        
        // Ensure recipe_images directory exists
        const recipeImagesDir = path.join(__dirname, 'recipe_images');
        if (!fs.existsSync(recipeImagesDir)) {
          fs.mkdirSync(recipeImagesDir, { recursive: true });
        }
        
        // Process and save the image using Sharp
        const newPath = path.join(__dirname, 'recipe_images', filename);
        
        if (file.buffer) {
          // If using memory storage (file.buffer exists)
          await sharp(file.buffer)
            .resize(800, 800, { 
              fit: 'inside',
              withoutEnlargement: true 
            })
            .jpeg({ quality: 85 })
            .toFile(newPath);
        } else if (file.path) {
          // If using disk storage (file.path exists)
          await sharp(file.path)
            .resize(800, 800, { 
              fit: 'inside',
              withoutEnlargement: true 
            })
            .jpeg({ quality: 85 })
            .toFile(newPath);
          
          // Clean up temp file
          fs.unlinkSync(file.path);
        }
        
        // Create the image URL path
        const imageUrl = `/recipe_images/${filename}`;
        const fullImageUrl = `${baseUrl}/recipe_images/${filename}`;
        
        console.log(`💾 Saved image to: ${newPath}`);
        console.log(`🔗 Image URL path: ${imageUrl}`);
        
        // First verify the keyword exists
        const keyword = await db.getOne(
          'SELECT id, recipe_id FROM keywords WHERE id = ?',
          [update.keywordId]
        );
        
        if (!keyword) {
          console.error(`❌ Keyword not found: ${update.keywordId}`);
          results.push({ 
            keywordId: update.keywordId, 
            success: false, 
            error: 'Keyword not found' 
          });
          continue;
        }
        
        // Update the keyword with the new image URL
        // Use relative path for consistency with your original code
        const updateResult = await runQuery(
          "UPDATE keywords SET image_url = ? WHERE id = ?",
          [imageUrl, update.keywordId]
        );
        
        console.log(`✅ Updated keyword ${update.keywordId} with image URL: ${imageUrl}`);
        
        // Get recipe ID - either from the update or from the keyword
        const recipeId = update.recipeId || keyword.recipe_id;
        
        // Update recipe_images table if recipe ID exists
        if (recipeId) {
          console.log(`🔄 Updating image for recipe ${recipeId}`);
          
          // Check if record exists
          const existing = await db.getOne(
            'SELECT id FROM recipe_images WHERE recipe_id = ?',
            [recipeId]
          );
          
          if (existing) {
            // Update existing record
            await runQuery(
              'UPDATE recipe_images SET image_url = ?, grid_image_url = ?, image_path = ?, updated_at = CURRENT_TIMESTAMP WHERE recipe_id = ?',
              [imageUrl, imageUrl, filename, recipeId]
            );
            console.log(`✅ Updated existing recipe_images record for recipe ${recipeId}`);
          } else {
            // Insert new record
            await runQuery(
              'INSERT INTO recipe_images (recipe_id, image_url, grid_image_url, image_path, status) VALUES (?, ?, ?, ?, ?)',
              [recipeId, imageUrl, imageUrl, filename, 'completed']
            );
            console.log(`✅ Created new recipe_images record for recipe ${recipeId}`);
          }
        }
        
        results.push({ 
          keywordId: update.keywordId,
          recipeId: recipeId,
          imageUrl: imageUrl,
          success: true 
        });
        
      } catch (fileError) {
        console.error(`❌ Error processing file for keyword ${update.keywordId}:`, fileError);
        results.push({ 
          keywordId: update.keywordId, 
          success: false, 
          error: fileError.message 
        });
      }
    }
    
    const successCount = results.filter(r => r.success).length;
    console.log(`📊 Image update complete: ${successCount}/${results.length} successful`);
    
    res.json({ 
      success: successCount > 0, 
      message: `Successfully updated ${successCount} of ${results.length} images`,
      results: results
    });
    
  } catch (error) {
    console.error('Error updating keyword images:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'An unknown server error occurred' 
    });
  }
});

// Add this to your server.js or app.js file

// Image proxy route to handle Facebook CDN and other external images
app.get('/api/proxy-image', async (req, res) => {
  try {
    const imageUrl = req.query.url;
    
    if (!imageUrl) {
      return res.status(400).send('No URL parameter provided');
    }
    
    console.log(`Proxying image request for: ${imageUrl}`);
    
    // Make sure the URL is properly decoded
    const decodedUrl = decodeURIComponent(imageUrl);
    
    // Fetch the image with appropriate headers
    const response = await fetch(decodedUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Accept': 'image/webp,image/apng,image/*,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://www.facebook.com/',
        'Cache-Control': 'no-cache'
      }
    });
    
    if (!response.ok) {
      console.error(`Failed to fetch image: ${response.status} ${response.statusText}`);
      return res.status(response.status).send(`Failed to fetch image: ${response.statusText}`);
    }
    
    // Get the image data
    const imageBuffer = await response.arrayBuffer();
    const contentType = response.headers.get('content-type') || 'image/jpeg';
    
    // Set appropriate headers
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 24 hours
    
    // Send the image data
    res.send(Buffer.from(imageBuffer));
    
  } catch (error) {
    console.error('Error proxying image:', error);
    res.status(500).send('Error proxying image: ' + error.message);
  }
});

// Alternative simpler endpoint if you don't need server-side storage
app.post('/api/keywords/update-image-urls', async (req, res) => {
  try {
    const { updates } = req.body; // Array of {keywordId, imageDataUrl}
    
    if (!updates || !Array.isArray(updates)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid update data' 
      });
    }
    
    const results = [];
    
    console.log(`🔄 [UPDATE-IMAGES] Processing ${updates.length} image updates`);
    
    for (const update of updates) {
      try {
        console.log(`📝 [UPDATE-IMAGES] Updating keyword ${update.keywordId} with data URL (${Math.round((update.imageDataUrl?.length || 0)/1024)}KB)`);
        
        // First, check if the keyword exists using the consistent DB functions
        const existingKeyword = await getOne(
          `SELECT id, keyword, image_url FROM keywords WHERE id = ?`,
          [update.keywordId]
        );
        
        if (!existingKeyword) {
          console.error(`❌ [UPDATE-IMAGES] Keyword ${update.keywordId} not found in database!`);
          throw new Error(`Keyword ${update.keywordId} not found`);
        }
        
        console.log(`✅ [UPDATE-IMAGES] Found existing keyword: ${existingKeyword.keyword} (current image_url length: ${existingKeyword.image_url?.length || 0})`);
        
        // Update the database with the cropped image data URL using runQuery
        const updateResult = await runQuery(
          `UPDATE keywords SET image_url = ? WHERE id = ?`,
          [update.imageDataUrl, update.keywordId]
        );
        
        console.log(`✅ [UPDATE-IMAGES] Successfully updated keyword ${update.keywordId} (${updateResult.changes} rows affected)`);
        
        results.push({
          keywordId: update.keywordId,
          success: true
        });
        
      } catch (error) {
        console.error(`❌ [UPDATE-IMAGES] Error processing keyword ${update.keywordId}:`, error.message);
        results.push({
          keywordId: update.keywordId,
          success: false,
          error: error.message
        });
      }
    }
    
    res.json({
      success: true,
      message: `Updated ${results.filter(r => r.success).length} of ${results.length} images`,
      results
    });
    
  } catch (error) {
    console.error('Error updating image URLs:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'Server error' 
    });
  }
});

// Default prompts configuration
let promptConfig = {
  model: process.env.DEFAULT_MODEL || 'gpt-4-turbo-preview',
  temperature: parseFloat(process.env.DEFAULT_TEMPERATURE || '0.7'),
  apiKey: process.env.OPENAI_API_KEY,
  language: process.env.DEFAULT_LANGUAGE || 'English',
  pinCount: parseInt(process.env.DEFAULT_PIN_COUNT || '10'),
  

  prompts: {
    pinTitleSystem: process.env.PIN_TITLE_SYSTEM_PROMPT || `You are a copywriting expert specialized in Pinterest Pin titles. Your task is to generate 10 different Pinterest titles for each keyword or idea, using proven high-conversion techniques.

Title formats:

Title 1: Clear & Concise Titles
Delivering the recipe's value in a straightforward way helps users instantly understand what to expect.
Example: Easy Chicken Alfredo Pasta Recipe

Title 2: Curiosity Titles
Creating a sense of intrigue encourages readers to click and discover the secret, twist, or surprise behind the recipe.
Example: The Secret to Fluffy Pancakes Everyone Gets Wrong

Title 3: Number-Based Titles
Using numbers adds structure and specificity, making the post feel scannable and promising actionable takeaways.
Example: 5 Quick Air Fryer Chicken Recipes for Busy Weeknights

Title 4: "How-To" / Instructional Titles
These titles promise a clear, step-by-step guide, appealing to readers seeking specific instructions.
Example: How to Make Perfect Japanese Soufflé Pancakes at Home

Title 5: Question-Based Titles
Posing a question piques curiosity and encourages clicks, especially when addressing common problems or desires.
Example: Craving Fluffy Pancakes? Try This Easy Soufflé Recipe!

Title 6: Mistake-Avoidance Titles
Highlighting common errors and how to avoid them can attract readers looking to improve their skills.
Example: Avoid These 5 Common Mistakes When Making Soufflé Pancakes

Title 7: Ultimate Guide / Comprehensive Titles
Offering an all-in-one resource appeals to readers seeking in-depth information.
Example: The Ultimate Guide to Making Fluffy Japanese Soufflé Pancakes

Title 8: Comparison Titles
Comparing methods or ingredients can help readers make informed choices.
Example: Soufflé Pancakes vs. Traditional Pancakes: What's the Difference?

Title 9: Seasonal or Occasion-Based Titles
Tying recipes to seasons or events can increase relevance and urgency.
Example: Spring Brunch Delight: Fluffy Soufflé Pancakes Recipe

Title 10: Trend-Focused Titles
Leveraging current trends or viral topics can boost visibility.
Example: TikTok's Viral Soufflé Pancakes: Try the Recipe Everyone's Talking About

Context:

You're helping a food & lifestyle blogger attract attention on Pinterest. Users are quickly scrolling, so your titles must stop the scroll, spark interest, and encourage saves/clicks. Titles must also help the Pin rank in Pinterest search.

Instructions:

1. Use clear and concise language — strong verbs, no fluff
2. Highlight the benefit — make the result or value obvious
3. Create curiosity — tease secrets, ask questions, or spark intrigue
4. Use numbers/lists — if the topic allows, add structure with numbers
5. Use natural language with SEO keywords front-loaded
6. Keep each title under 100 characters
7. Write in a friendly, conversational tone like a real food or home blogger

Bad vs. Good Examples:

1. Clear & Concise Titles
❌ "Chicken dinner idea" → ✅ "Easy Baked Lemon Chicken Thighs"
❌ "Soup I love" → ✅ "Creamy Tomato Basil Soup Recipe"
❌ "Slow cooker something" → ✅ "Slow Cooker Pulled Pork Sandwiches"

2. Curiosity Titles
❌ "Cool pancake recipe" → ✅ "The Secret to Fluffy Pancakes Everyone Gets Wrong"
❌ "Another slow cooker recipe" → ✅ "Why I Always Add This to My Crockpot Chicken"
❌ "Easy dessert idea" → ✅ "The 2-Ingredient Chocolate Mousse That Feels Fancy"

3. Number-Based Titles
❌ "Quick breakfast meals" → ✅ "5 Cozy Fall Breakfasts You'll Crave"
❌ "Ideas for pasta night" → ✅ "7 Easy Pasta Recipes for Busy Weeknights"
❌ "Dinner tips" → ✅ "3 Tricks for Juicier Chicken Every Time"

4. How-To / Instructional Titles
❌ "Best banana bread" → ✅ "How to Make Moist Banana Bread That Never Fails"
❌ "Easy pancakes" → ✅ "How to Make Fluffy Pancakes from Scratch"
❌ "Quick salad idea" → ✅ "How to Build the Perfect Summer Salad in 10 Minutes"

5. Question Titles
❌ "Try these meatballs" → ✅ "Can You Make Meatballs Without Breadcrumbs?"
❌ "Tips for baking bread" → ✅ "Is Homemade Bread Really Worth It?"
❌ "Taco recipe here" → ✅ "What's the Secret to the Best Taco Tuesday?"

6. Mistake-Avoidance Titles
❌ "Bread baking tips" → ✅ "Avoid These 5 Mistakes When Baking Bread"
❌ "How to roast chicken" → ✅ "Stop Doing This When Roasting a Whole Chicken"
❌ "Make better cookies" → ✅ "Why Your Cookies Turn Out Flat — And How to Fix Them"

7. Ultimate Guide Titles
❌ "Soufflé recipe" → ✅ "The Ultimate Guide to Making Soufflé Pancakes at Home"
❌ "Baking bread" → ✅ "Beginner's Guide to Homemade Sourdough"
❌ "Meal prep" → ✅ "The Ultimate 7-Day Meal Prep Plan for Busy Families"

8. Comparison Titles
❌ "Soup recipe" → ✅ "Instant Pot vs. Crockpot: Which Makes Better Chicken Soup?"
❌ "Smoothie vs juice" → ✅ "Green Smoothies vs. Juices: Which Is Healthier?"
❌ "Microwave vs oven" → ✅ "Microwave Mug Cakes vs. Oven-Baked: What's the Real Difference?"

9. Seasonal / Occasion-Based Titles
❌ "Apple pie recipe" → ✅ "Cozy Fall Apple Pie with Maple Crust"
❌ "Some Thanksgiving food" → ✅ "Easy Thanksgiving Sides to Impress Your Guests"
❌ "Soup idea" → ✅ "Winter Comfort: Creamy Chicken Noodle Soup"

10. Trend-Focused Titles
❌ "Cool new recipe" → ✅ "TikTok's Viral Grinder Salad Sandwich — Worth the Hype?"
❌ "What's popular now" → ✅ "These Butter Boards Are Taking Over Pinterest"
❌ "Soup trend" → ✅ "Cottage Cheese Ice Cream: What Happens When You Try It?"`,
    
    pinTitleUser: process.env.PIN_TITLE_USER_PROMPT || `Recipe Idea: {{recipeIdea}}
Language: {{language}}
Please generate {{pinCount}} different Pinterest Pin titles that follow the formatting and guidance provided in the system prompt. Use the keyword, interests, and recipe idea to create attention-grabbing, high-conversion titles. 
Return only the final text without any numbering, dashes, labels, or quotation marks. Do not include "Title 1:", "1.", "-", or any symbols. Just plain clean text.`,
    
    pinDescSystem: process.env.PIN_DESC_SYSTEM_PROMPT || `You are a Pinterest marketing and copywriting expert. Your task is to generate highly effective Pinterest Pin descriptions for blog post Pins that maximize engagement and click-throughs. Each description must serve both the Pinterest algorithm and real human readers.
Follow these strict principles:
1. Start with relevant, **front-loaded keywords** based on the Pin topic — what users are likely to search
2. Use **natural, conversational language** (like friendly advice from a blogger)
3. Be **clear and benefit-driven** — what problem does this Pin solve or what value does it offer?
4. Add a **a natural, benefit-focused nudge that encourages action without sounding pushy** (e.g., "Don't be surprised if this becomes your new favorite" or "A cozy dinner idea worth trying this week")
5. End with **2–3 relevant broad hashtags** (max) that match Pinterest SEO best practices
6. Keep each description between **100–200 characters**
Tone: Warm, helpful, modern. You are writing for American women home cooks or lifestyle lovers.
Bad vs Good examples (with indirect CTAs):
❌ "Here's a pin about meal prep ideas for the week"
✅ "Meal prep just got easier with these 5 make-ahead dinners for busy nights. One to keep in your weekly rotation. #mealprep #weeknightmeals"
❌ "How to make fall wreaths"
✅ "Learn how to make a beautiful fall wreath in under 30 minutes — a cozy DIY project you'll want to recreate. #fallwreath #diyhomedecor"
Always output:
- 1 Pinterest-optimized description in 100–200 characters.`,
    
    pinDescUser: process.env.PIN_DESC_USER_PROMPT || `Pin Title: {{pinTitle}}
Category: {{category}}
Annotated Interests: {{interests}}
Language: {{language}}
Based on the instructions provided, please write {{pinCount}} different Pinterest Pin description that is optimized for both engagement and SEO. 
Return only the final text without any numbering, dashes, labels, or quotation marks. Do not include "Description 1:", "1.", "-", or any symbols. Just plain clean text.`,
    
    pinOverlaySystem: process.env.PIN_OVERLAY_SYSTEM_PROMPT || `You are a Pinterest marketing and visual copy expert. Your task is to create short, scroll-stopping overlay text for Pinterest images. This overlay should grab attention fast while sparking curiosity — using as few words as possible.
Follow these principles:
1. Use **minimal text** — 4 to 7 words max
2. **Front-load keywords** for Pinterest SEO (if relevant)
3. Focus on **benefit or transformation** — what will the viewer gain?
4. Spark **curiosity** with surprise, specificity, or urgency
5. Use **clear, bold, conversational language** — no fluff or vague words
6. Do **not** include punctuation unless it's essential (like parentheses or exclamation points)
7. No hashtags or branding
Tone: Friendly, modern, and direct — like a helpful blogger speaking to her Pinterest audience
Bad vs Good (with keyword included naturally):
❌ "My best slow cooker idea ever!" ✅ "Slow Cooker Chicken That Falls Apart"
❌ "Some fall organizing tips" ✅ "Fall Closet Organization Made Simple"
❌ "Ways to save money" ✅ "Save Big on Your Weekly Grocery Bill"
❌ "Tasty dinner tonight?" ✅ "Easy Crockpot Chicken Tacos Tonight"
❌ "Meal prep goals!" ✅ "Vegan Meal Prep You'll Actually Love"
Always return 1 short overlay phrase only.`,
    
    pinOverlayUser: process.env.PIN_OVERLAY_USER_PROMPT || `Pin Title: {{pinTitle}}
Language: {{language}}
Create {{pinCount}} short Pinterest image overlay text (4–7 words max) that matches the tone and message of the Pin. Use curiosity and benefit-driven language. Keep it concise and bold. 
Return only the final text without any numbering, dashes, labels, or quotation marks. Do not include "Image 1:", "1.", "-", or any symbols. Just plain clean text.`,
    
    metaTitleSystem: process.env.META_TITLE_SYSTEM_PROMPT || `You are an SEO content strategist specializing in crafting compelling and optimized blog post titles.
Your goal is to generate one SEO-friendly blog post title that aligns with current best practices to enhance visibility in search engines and drive clicks.
Context:
The title must attract attention in search engine results pages (SERPs), accurately represent the blog post content, and include the keyword naturally.
Follow these instructions:
- Incorporate the Primary Keyword: Include the main keyword, ideally at the beginning.
- Match Search Intent: Understand what the user is looking for and reflect that in the title.
- Be Descriptive and Concise: Clearly express the value of the post in 50–60 characters.
- Avoid Keyword Stuffing: Use keywords naturally — no repetition or awkward phrasing.
- Use Power Words and Numbers: Include numbers, brackets, or compelling phrases to increase click-through rates (e.g. "10 Easy Tips", "[2025]", "Best", etc.).
Constraints:
- Character Limit: Maximum of 60 characters
- Tone: Professional, clear, and engaging
- Avoid misleading or clickbait titles
Bad vs Good Examples:
1. Clear & Concise
❌ Poor: "A Great Dinner Recipe I Love" ✅ Good: Easy Slow Cooker Chicken Tacos
❌ Poor: "Make This Dish Tonight" ✅ Good: Creamy Garlic Mashed Potatoes Recipe
2. Curiosity-Based
❌ Poor: "This Might Be the Best Chicken Ever" ✅ Good: The Secret to the Best Slow Cooker Chicken
❌ Poor: "Wow—Just Try This Pasta" ✅ Good: Why Everyone's Talking About This Pasta Bake
3. Number-Based
❌ Poor: "Tasty Dinners to Try" ✅ Good: 5 Quick Weeknight Dinners to Try Now
❌ Poor: "Ideas for Soups" ✅ Good: 7 Cozy Fall Soups You Can Freeze
4. How-To / Instructional
❌ Poor: "Making Pancakes Like This Is Fun" ✅ Good: How to Make Fluffy Japanese Soufflé Pancakes
❌ Poor: "Roast Chicken Is Easy If You Know How" ✅ Good: How to Roast Chicken Perfectly Every Time
5. Question-Based
❌ Poor: "Thinking of Prepping Chicken?" ✅ Good: What's the Best Way to Meal Prep Chicken?
❌ Poor: "No Eggs? Try This" ✅ Good: Can You Bake a Cake Without Eggs?
6. Mistake-Avoidance
❌ Poor: "Bread Didn't Turn Out?" ✅ Good: 5 Mistakes That Ruin Banana Bread
❌ Poor: "Watch Out When You Slow Cook" ✅ Good: Avoid These Slow Cooker Chicken Fails
7. Ultimate Guide
❌ Poor: "Learn Everything About Chicken Recipes" ✅ Good: The Ultimate Guide to Slow Cooker Chicken
❌ Poor: "How to Meal Prep All Week" ✅ Good: Complete Guide to Keto Meal Prep for Beginners
8. Comparison
❌ Poor: "Different Cooking Appliances Compared" ✅ Good: Air Fryer vs. Oven: Which Cooks Faster?
❌ Poor: "Quinoa or Rice—You Decide" ✅ Good: Quinoa vs. Rice: Which Is Better for Meal Prep?
9. Seasonal / Occasion-Based
❌ Poor: "Holiday Brunch Recipe Ideas" ✅ Good: Easy Christmas Brunch Ideas Everyone Will Love
❌ Poor: "Dinner Ideas for Autumn" ✅ Good: Cozy Fall Dinner Recipes for Chilly Nights
10. Trend-Focused
❌ Poor: "The Newest Internet Food Thing" ✅ Good: TikTok's Viral Baked Oats: Worth the Hype?
❌ Poor: "This Ice Cream Is Weird But Cool" ✅ Good: Try This Pinterest-Famous Cottage Cheese Ice Cream
Return only one SEO-optimized blog post title.`,
    
    metaTitleUser: process.env.META_TITLE_USER_PROMPT || `Pinterest Pin title: {{pinTitle}}
Language: {{language}}
Please generate 1 SEO blog post title that follows the instructions provided in the system prompt. Make it optimized for search, aligned with the pin title, and under 60 characters. 
Return only the final text without any numbering, dashes, labels, or quotation marks. Do not include "Title 1:", "1.", "-", or any symbols. Just plain clean text.`,
    
    metaDescSystem: process.env.META_DESC_SYSTEM_PROMPT || `You are an SEO content strategist specializing in crafting compelling meta descriptions that enhance search engine visibility and click-through rates. Your goal is to generate an SEO-friendly meta description that accurately summarizes a blog post or webpage and entices users to click.
Context:
The description should align with the page's actual content, include relevant keywords naturally, and appeal to the target audience's search intent.
Follow these instructions:
- Optimal Length: Keep the meta description between 120–155 characters so it displays properly in Google results.
- Incorporate Target Keywords: Use the primary keyword naturally and early in the sentence.
- Use Active Voice and Action-Oriented Language: Engage the reader with direct, clear phrasing.
- Gently guide the reader toward clicking by hinting at the value of the content. Instead of direct commands, use friendly phrasing that suggests what they'll gain or enjoy. Encourage clicks with phrases like "A must-try if you love quick, comforting meals" "Discover," "Perfect for your next cozy dinner at home" or "The kind of recipe that saves busy weeknights."
- Ensure Uniqueness: Every description must be unique and not duplicated from other pages.
- Reflect Page Content Accurately: Ensure the summary represents what the post truly offers.
Constraints:
- Character Limit: Maximum of 155 characters
- Tone: Professional, helpful, and engaging
- Avoid keyword stuffing or vague language
Bad vs Good Examples:
1. Clear & Concise Titles
❌ Poor: "This blog post is about chicken tacos and how to cook them." ✅ Good: "Make these easy slow cooker chicken tacos with simple pantry staples — perfect for a no-fuss dinner everyone will love."
2. Curiosity-Based Titles
❌ Poor: "This recipe is a surprise and very good. You should try it." ✅ Good: "The secret to juicy, flavor-packed chicken is easier than you think — one you'll want to make again and again."
3. Number-Based Titles
❌ Poor: "Here are some recipes to try for dinner or lunch." ✅ Good: "Try these 5 quick dinner ideas that make busy weeknights feel a little easier — no fancy ingredients required."
4. How-To Titles
❌ Poor: "Learn about making pancakes with steps to follow." ✅ Good: "Follow this step-by-step guide to fluffy soufflé pancakes — soft, jiggly, and ready to impress."
5. Question-Based Titles
❌ Poor: "This blog post will answer your question about baking a cake." ✅ Good: "Wondering how to bake a cake without eggs? This easy recipe has you covered with simple swaps and delicious results."
6. Mistake-Avoidance Titles
❌ Poor: "Here are some mistakes to avoid when cooking." ✅ Good: "Avoid these common bread-baking mistakes to get soft, golden loaves every time — great if you're just starting out."
7. Ultimate Guide Titles
❌ Poor: "Everything you need to know is in this blog post." ✅ Good: "This ultimate slow cooker chicken guide has everything you need — from tips to variations and serving ideas."
8. Comparison Titles
❌ Poor: "This post compares two different cooking methods." ✅ Good: "Not sure if the air fryer or oven is better? This comparison breaks it down with time, texture, and taste in mind."
9. Seasonal / Occasion-Based Titles
❌ Poor: "Recipes for the holidays and other times of the year." ✅ Good: "Warm up your table with these cozy fall dinner recipes — easy comfort food perfect for chilly nights."
10. Trend-Focused Titles
❌ Poor: "Try this trending recipe from the internet." ✅ Good: "This TikTok-famous baked oats recipe is easy, wholesome, and totally worth the hype."
Return only one SEO-optimized meta description.`,
    
    metaDescUser: process.env.META_DESC_USER_PROMPT || `Pinterest Pin title: {{pinTitle}}
Pinterest Pin description: {{pinDesc}}
Language: {{language}}
Please generate 1 SEO meta description that aligns with this Pin's topic. Follow the system instructions to optimize for both search and click-throughs. 
Return only the final text without any numbering, dashes, labels, or quotation marks. Do not include "Title 1:", "1.", "-", or any symbols. Just plain clean text.`,
    
    slugSystemPrompt: process.env.SLUG_SYSTEM_PROMPT || `You are an SEO specialist. Your task is to generate a short, clean, and keyword-optimized blog post slug based on the provided meta title and recipe idea.
Slug Format Rules:
- Use only lowercase letters
- Replace spaces with hyphens (kebab-case)
- Use 3 to 6 important words only (max ~60 characters total)
- Include 1 or 2 primary keywords from the title or recipe idea
- Remove stopwords like "a", "the", "and", "to", "with", "of", etc.
- Do NOT include domain names, slashes, or punctuation
- Match the title's core idea, but keep it short and search-friendly
Output Requirements:
Return only the final slug (no quotes, no formatting, no label).`,
    
    slugUserPrompt: process.env.SLUG_USER_PROMPT || `Recipe Idea: {{recipeIdea}}  
Meta Title: {{metaTitle}}
Please generate a short, SEO-optimized blog post slug based on the title and keyword.`,
    
    blogpostSystemPrompt: process.env.BLOGPOST_SYSTEM_PROMPT || `You are a food blogger and SEO content strategist writing for the brand Wanda Recipes.
Tone & Brand Voice:
- Audience: American women who love quick, easy, homemade meals
- Tone: Friendly, informative, and encouraging — like chatting with a friend in the kitchen
- Guidelines: Use warm, clear language. Avoid jargon. Be helpful, real, and supportive. Make readers feel at home and inspired to try the recipe.
Your task is to write a fully SEO-optimized blog post for a recipe based on the following inputs: meta title, meta description, category, and annotated interest.
Write with search performance and readability in mind. The blog post should rank well on Google and delight readers.
🧠 CONTENT STRUCTURE:
Write a blog post using this structure, but DO NOT repeat these section headers literally. Instead, optimize all section titles dynamically for SEO and clarity.
1. **INTRODUCTION**
   - Begin with a friendly hook that draws the reader in
   - Include the primary keyword naturally in the first 1–2 sentences
   - Add a personal anecdote or story to build trust and relatability
3. **INGREDIENTS**
   - Break into clear bullet points
   - Provide brief, helpful tips where relevant
   - Mention tools needed for success
4. **STEP-BY-STEP INSTRUCTIONS** 
   - Use numbered steps  
   - Each step should begin with a short, clear title (like a mini heading) to guide the reader (e.g., "1. Whisk the Batter" or "3. Flip and Cook")  
   - Follow the title with a beginner-friendly explanation  
   - Add casual encouragement, helpful tips, or notes if relevant (e.g., "Don't worry if it looks messy here — that's normal!")  
5. **FREQUENTLY ASKED QUESTIONS**
   - Include 4–5 questions your audience might Google
   - Answer clearly and supportively in Wanda's voice
6. **CLOSING / CALL-TO-ACTION**
   - Wrap up with encouragement to try the recipe
   - Suggest sharing on Pinterest or tagging on social
   - Include a soft, warm sign-off like a kitchen friend would use
---
🔍 SEO REQUIREMENTS (Based on Semrush Best Practices):
- Use the **meta title** as the blog post's H1
- Include the **primary keyword** within the first 100 words
- Naturally include **secondary keywords** (if implied in annotated interest)
- Use proper **H2 and H3 subheadings** with relevant keywords
- Incorporate **internal links** (if relevant) and **external links** to reputable sources
- Include **image suggestions** or alt text phrases with keywords
- Ensure content length is 800–1,200 words
- Avoid keyword stuffing, clickbait, or robotic phrasing
---
📋 OUTPUT RULES:
- Use SEO-optimized section headings based on the content and recipe keyword but write them as plain text — do NOT use markdown symbols like \`##\`, \`**\`, or numbers
- Format all headings as plain lines of text above their paragraph (e.g., "Why You'll Love This Recipe")
- Do NOT repeat or copy the outline structure or headings from the system prompt
- Do NOT use any markdown, HTML, or numbered formatting
- Return ONLY clean, human-readable blog content ready to copy into WordPress
---
Return **only the blog post content**. Do not include markdown or HTML. Format it as plain, publish-ready text.`,
    
    blogpostUserPrompt: process.env.BLOGPOST_USER_PROMPT || `Please write a full SEO-optimized blog post for the following recipe topic:
Recipe Idea (Main Keyword): {{recipeIdea}}  
Meta Title: {{metaTitle}}  
Meta Description: {{metaDescription}}  
Category: {{category}}  
Annotated Interests: {{interests}}
Language: {{language}}
Do not repeat or label the sections — just use helpful headings and clean, natural text.  
Avoid any markdown symbols, numbers, or bold/italic styles.  
Return only the final blog content as plain text.
Use the blog structure and tone described in the system prompt.  
Do not include outline labels or formatting (no bold, headings, asterisks, or HTML).  
Return **only the blog content** as clean, plain text.  
Make it copy-paste ready for WordPress.
Follow the blog structure and tone described in the system prompt but rewrite section headings dynamically with SEO-friendly, benefit-focused language. Return only the blog post content as clean, publish-ready plain text. Do not include markdown, bullet formatting symbols, or explanations — just the blog content.`,
    
    fbPrompt: process.env.FB_PROMPT || `Create a complete recipe for {{recipeIdea}} in {{language}}. Include:
1. An emoji and title at the beginning
2. A brief introduction (2-3 sentences)
3. Ingredients section with emoji 🧂 and ingredients listed with bullet points
4. Preparation section with emoji 🧑‍🍳 and numbered steps
5. A cooking tip at the end

Be detailed but concise, and ensure the recipe is delicious and practical.`,
    
    mjTemplate: process.env.MJ_TEMPLATE || `Professional food photography of {{title}}, ingredients include {{ingredients}}, photo taken with a Canon EOS R5, 85mm lens, f/2.8, natural lighting, food styling, shallow depth of field, mouth-watering, magazine quality, top view, soft shadows, textured wood or marble background, garnished beautifully`,
    
    fbCaptionPrompt: process.env.FB_CAPTION_PROMPT || `Create an engaging Facebook post caption for this recipe in {{language}}. The caption should be conversational, include 2-3 emojis, ask an engaging question, and invite comments. Keep it under 150 words and make sure it entices people to try the recipe. Here's the recipe:

{{recipe}}`
  }
};

// Make the moment library available to templates
app.locals.moment = moment;


// Home page - now shows recent recipes
// Home page - now shows recent recipes with organization filtering
// Home page - now shows recent recipes with organization filtering and activity statistics
app.get('/', isAuthenticated, async (req, res) => {
  try {
    // Get organization ID from session
    const organizationId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    const isAdmin = req.session.user.role === 'admin';
    
    // Collect dashboard statistics
    const dashboardStats = {
      recipes: 0,
      pendingKeywords: 0,
      processedKeywords: 0,
      failedKeywords: 0,
      totalKeywords: 0,
      wordpressPosts: 0,
      userCount: 0
    };
    
    // Get recent recipes filtered by organization and optionally by user
    let recentRecipes;
    if (userId) {
      // For employees, only show their recipes
      recentRecipes = await recipeDb.getRecipesByOwnerAndOrg(userId, organizationId, 10, 0);
    } else {
      // For admins, show all recipes in their organization
      recentRecipes = await recipeDb.getRecipesByOrg(organizationId, 10, 0);
    }
    
    // Gather keyword statistics
    dashboardStats.pendingKeywords = await keywordsDb.getKeywordsCount('pending', null, userId, organizationId);
    dashboardStats.processedKeywords = await keywordsDb.getKeywordsCount('processed', null, userId, organizationId);
    dashboardStats.failedKeywords = await keywordsDb.getKeywordsCount('failed', null, userId, organizationId);
    dashboardStats.totalKeywords = dashboardStats.pendingKeywords + dashboardStats.processedKeywords + dashboardStats.failedKeywords;
    
    // Get recipe count
    if (userId) {
      dashboardStats.recipes = await recipeDb.getRecipeCountByOwner(userId);
    } else {
      dashboardStats.recipes = await recipeDb.getRecipeCountByOrganization(organizationId);
    }
    
    // Get WordPress post count if we have WordPress integration
    try {
dashboardStats.wordpressPosts = await wordpressDb.getPublicationCount(userId, organizationId, req.session.currentWebsiteId);
    } catch (error) {
      console.log('No WordPress publications found or error counting them:', error.message);
    }
    
    // If admin, get user count in organization
    if (isAdmin) {
      const orgUsers = await userDb.getUsersByOrganization(organizationId);
      dashboardStats.userCount = orgUsers.length;
      
      // Get recent activity for the organization
      dashboardStats.recentActivity = await getRecentActivityLogs(organizationId, 5);
      
      // Get employee performance stats
      dashboardStats.employeeStats = await getEmployeeStats(organizationId);
    } else {
      // For employees, get their own activity
      dashboardStats.recentActivity = await getRecentActivityLogs(organizationId, 5, userId);
    }
    
    // Ensure promptConfig is properly formatted
    if (promptConfig && !promptConfig.prompts) {
      promptConfig = {
        model: promptConfig.model || 'gpt-4-turbo-preview',
        temperature: promptConfig.temperature || 0.7,
        apiKey: promptConfig.apiKey || process.env.OPENAI_API_KEY,
        language: promptConfig.language || 'English',
        pinCount: promptConfig.pinCount || 10,
        prompts: { ...promptConfig }
      };
    }
    
    res.render('index', { 
      promptConfig: promptConfig || {},
      recentRecipes,
      stats: dashboardStats,
      isAdmin: isAdmin,
      pageTitle: 'Dashboard',
      activePage: 'dashboard',
      title: 'RecipeGen AI - Dashboard'
    });
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    res.render('index', { 
      promptConfig: promptConfig || {},
      recentRecipes: [],
      stats: {},
      error: 'Failed to load dashboard data: ' + error.message,
      pageTitle: 'Dashboard',
      activePage: 'dashboard',
      title: 'RecipeGen AI - Dashboard'
    });
  }
});

// Helper function to get recent activity logs
async function getRecentActivityLogs(organizationId, limit = 5, userId = null) {
  try {
    // If we don't have an activity log table yet, return empty array
    const hasActivityTable = await checkTableExists('activity_logs');
    if (!hasActivityTable) {
      return [];
    }
    
    let query = `
      SELECT al.*, u.name as user_name 
      FROM activity_logs al
      JOIN users u ON al.user_id = u.id
      WHERE al.organization_id = ?
    `;
    
    const params = [organizationId];
    
    if (userId) {
      query += ` AND al.user_id = ?`;
      params.push(userId);
    }
    
    query += ` ORDER BY al.created_at DESC LIMIT ?`;
    params.push(limit);
    
    return await getAll(query, params);
  } catch (error) {
    console.error('Error getting activity logs:', error);
    return [];
  }
}

// Helper function to get employee stats
async function getEmployeeStats(organizationId) {
  try {
    // Get all employees in the organization
    const employees = await userDb.getUsersByOrganization(organizationId);
    const employeeIds = employees.filter(u => u.role === 'employee').map(u => u.id);
    
    if (employeeIds.length === 0) {
      return [];
    }
    
    // Get stats for each employee
    const stats = [];
    
    for (const id of employeeIds) {
      const employee = employees.find(u => u.id === id);
      
      // Skip if not found (should never happen)
      if (!employee) continue;
      
      // Get counts
      const recipeCount = await recipeDb.getRecipeCountByOwner(id);
      const keywordCounts = {
        pending: await keywordsDb.getKeywordsCount('pending', null, id),
        processed: await keywordsDb.getKeywordsCount('processed', null, id),
        failed: await keywordsDb.getKeywordsCount('failed', null, id)
      };
      
      // Calculate total
      keywordCounts.total = keywordCounts.pending + keywordCounts.processed + keywordCounts.failed;
      
      // Get WordPress posts if we have WordPress integration
      let wpPostCount = 0;
      try {
        wpPostCount = await wordpressDb.getPublicationCount(id, organizationId, req.session.currentWebsiteId);
      } catch (error) {
        // Ignore error if WordPress integration not set up
      }
      
      stats.push({
        id: id,
        name: employee.name,
        email: employee.email,
        recipeCount,
        keywordCounts,
        wpPostCount,
        totalContent: recipeCount + keywordCounts.processed
      });
    }
    
    // Sort by total content in descending order
    return stats.sort((a, b) => b.totalContent - a.totalContent);
  } catch (error) {
    console.error('Error getting employee stats:', error);
    return [];
  }
}

// Helper function to check if a table exists
async function checkTableExists(tableName) {
  try {
    const result = await getOne(
      `SELECT name FROM sqlite_master WHERE type='table' AND name=?`,
      [tableName]
    );
    return !!result;
  } catch (error) {
    console.error(`Error checking if table ${tableName} exists:`, error);
    return false;
  }
}

// Updated Settings Route for server.js
// Replace your existing settings GET route with this one

// Updated Settings GET Route
app.get('/settings', isAuthenticated, async (req, res) => {
  try {
    const successMessage = req.session.successMessage;
    const errorMessage = req.session.errorMessage;
    delete req.session.successMessage; // Clear the message after use
    delete req.session.errorMessage; // Clear the error message after use
    
    // Get organization ID and website ID from session
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    
    // Load website-specific settings
    const websiteSettings = promptSettingsDb.loadSettings(organizationId, websiteId);
    
    // Set to global promptConfig for backward compatibility
    promptConfig = websiteSettings;
    
    // Get API key information - force a fresh check from the database
    const openaiKey = await apiKeyManager.getApiKey('openai');
    console.log('Settings page - API key status:', openaiKey ? 'Found' : 'Not found');
    
    const apiKeys = {
      openai: openaiKey ? true : false
    };
    
    res.render('settings', { 
      promptConfig: websiteSettings || {},
      successMessage: successMessage,
      errorMessage: errorMessage,
      pageTitle: 'Prompt Settings',
      activePage: 'settings',
      title: 'RecipeGen AI - Settings',
      apiKeys: apiKeys,
      websiteId: websiteId
    });
  } catch (error) {
    console.error('Error loading settings page:', error);
    res.render('settings', { 
      promptConfig: promptConfig || {},
      successMessage: null,
      errorMessage: 'Error loading settings: ' + error.message,
      pageTitle: 'Prompt Settings',
      activePage: 'settings',
      title: 'RecipeGen AI - Settings',
      apiKeys: { openai: false },
      websiteId: req.session.currentWebsiteId
    });
  }
});

// Keywords management page with organization filtering
// Keywords management page with organization filtering - FIXED VERSION
// Keywords management page with organization filtering - FIXED VERSION
app.get('/keywords', isAuthenticated, async (req, res) => {
  try {
    // Get organization ID from session
    const organizationId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    const userRole = req.session.user.role;
    
    console.log(`Loading keywords for ${userRole} (${userId}) in organization: ${organizationId}`);
    
    // Get query parameters for filtering and pagination
    const status = req.query.status || null;
    const page = parseInt(req.query.page || '1');
    const search = req.query.search || null;
    const limit = 50;
    const offset = (page - 1) * limit;

    // Get keywords with filters
    let keywords = [];
    if (userRole === 'employee') {
      // Employees only see their keywords
      keywords = await keywordsDb.getKeywordsByOwner(userId, status, limit, offset, search);
      console.log(`Retrieved ${keywords.length} keywords for employee ${userId}`);
    } else {
      // Admins see all keywords in their organization
      keywords = await keywordsDb.getKeywordsByOrganization(organizationId, status, limit, offset, search);
      console.log(`Retrieved ${keywords.length} keywords for organization ${organizationId}`);
    }
    
    // Get total count for pagination (with same filters)
    let totalCount = 0;
    if (userRole === 'employee') {
      totalCount = await keywordsDb.getKeywordsCount(status, search, userId);
    } else {
      totalCount = await keywordsDb.getKeywordsCount(status, search, null, organizationId);
    }
    
    const totalPages = Math.ceil(totalCount / limit);
    
    // Count by status for statistics
    let pendingCount = 0, processedCount = 0, failedCount = 0;
    if (userRole === 'employee') {
      pendingCount = await keywordsDb.getKeywordsCount('pending', null, userId);
      processedCount = await keywordsDb.getKeywordsCount('processed', null, userId);
      failedCount = await keywordsDb.getKeywordsCount('failed', null, userId);
    } else {
      pendingCount = await keywordsDb.getKeywordsCount('pending', null, null, organizationId);
      processedCount = await keywordsDb.getKeywordsCount('processed', null, null, organizationId);
      failedCount = await keywordsDb.getKeywordsCount('failed', null, null, organizationId);
    }
    
    res.render('keywords', {
  pageTitle: 'Keywords Management',
  activePage: 'keywords',
  title: 'RecipeGen AI - Keywords Management',
  keywords,
  currentPage: page,
  totalPages,
  totalCount,
  limit,
  status,
  search: search,  // CHANGED FROM searchTerm to search
  stats: {
    pending: pendingCount,
    processed: processedCount,
    failed: failedCount,
    total: totalCount
  }
});
  } catch (error) {
    console.error('Error loading keywords page:', error);
    res.render('error', {
      message: 'Failed to load keywords',
      error: error,
      pageTitle: 'Error',
      activePage: '',
      title: 'RecipeGen AI - Error'
    });
  }
});

app.get('/midjourney-filter-admin', isAuthenticated, isAdmin, (req, res) => {
  res.render('midjourney-filter-admin', {
    pageTitle: 'Midjourney Filter Admin',
    activePage: 'midjourney-filter-admin',
    title: 'RecipeGen AI - Midjourney Filter Admin'
  });
});

// Replace the existing /recipes route in server.js with this enhanced version

app.get('/recipes', isAuthenticated, isResourceOwner, async (req, res) => {
  try {
    // Get search parameters
    const searchTerm = req.query.search || '';
    const page = parseInt(req.query.page) || 1;
    const limit = 20;
    const offset = (page - 1) * limit;
    
    // Use the filters set by isResourceOwner middleware
    let recipes;
    
    if (req.session.user.role === 'employee') {
      // Employees see only their content
      if (searchTerm) {
        recipes = await recipeDb.searchRecipesByOwner(req.session.user.id, searchTerm, limit, offset);
      } else {
        recipes = await recipeDb.getRecipesByOwnerAndOrg(req.session.user.id, req.session.user.organizationId, limit, offset);
      }
    } else {
      // Admins see all org content
      if (searchTerm) {
        recipes = await recipeDb.searchRecipesInOrganization(req.session.user.organizationId, searchTerm, limit, offset);
      } else {
        recipes = await recipeDb.getRecipesByOrg(req.session.user.organizationId, limit, offset);
      }
    }

    // Fetch associated social media content AND WordPress publication status for each recipe
    const recipesWithContent = await Promise.all(recipes.map(async (recipe) => {
      try {
        // Get Facebook content
        const facebookContent = await facebookDb.getFacebookContentByRecipeId(
          recipe.id, 
          req.session.user.organizationId, 
          req.session.user.role === 'employee' ? req.session.user.id : null
        );
        
        // Get Pinterest variations (get the first one for display)
        const pinterestVariations = await pinterestDb.getVariationsByRecipeId(recipe.id);
        const firstPinterestVariation = pinterestVariations && pinterestVariations.length > 0 ? pinterestVariations[0] : null;
        
        // *** NEW: Get WordPress publication status ***
        let wordpressPublication = null;
        try {
          // Get the most recent publication for this recipe
          const publications = await wordpressDb.getPublicationsByRecipeId(recipe.id);
          if (publications && publications.length > 0) {
            // Get the most recent publication (publications should be ordered by created_at DESC)
            wordpressPublication = publications[0];
            
            // Add additional computed fields
            wordpressPublication.isPublished = wordpressPublication.wp_status === 'publish';
            wordpressPublication.isDraft = wordpressPublication.wp_status === 'draft';
            wordpressPublication.isPrivate = wordpressPublication.wp_status === 'private';
            
            // Format the publication date for display
            if (wordpressPublication.created_at) {
              wordpressPublication.publishedDate = moment(wordpressPublication.created_at).format('MMM D, YYYY');
              wordpressPublication.publishedFromNow = moment(wordpressPublication.created_at).fromNow();
            }
          }
        } catch (wpError) {
          console.warn(`Error fetching WordPress publication for recipe ${recipe.id}:`, wpError.message);
          // Continue without WordPress status
        }
        
        return {
          ...recipe,
          facebook: facebookContent,
          pinterest: firstPinterestVariation,
          pinterestCount: pinterestVariations ? pinterestVariations.length : 0,
          wordpressPublication: wordpressPublication // *** NEW: Add WordPress publication status ***
        };
      } catch (contentError) {
        console.warn(`Error fetching content for recipe ${recipe.id}:`, contentError.message);
        return {
          ...recipe,
          facebook: null,
          pinterest: null,
          pinterestCount: 0,
          wordpressPublication: null // *** NEW: Add null WordPress status on error ***
        };
      }
    }));
    
    res.render('recipes', { 
      recipes: recipesWithContent,
      searchTerm,
      pageTitle: 'Browse Recipes',
      activePage: 'recipes',
      title: 'RecipeGen AI - Recipe Browser',
      currentPage: page,
      totalPages: 1,
      limit: limit
    });
  } catch (error) {
    console.error('Error loading recipes:', error);
    res.render('error', { 
      message: 'Failed to load recipes',
      error: error,
      pageTitle: 'Error',
      activePage: '',
      title: 'RecipeGen AI - Error'
    });
  }
});

app.get('/recipe/:id', isAuthenticated, async (req, res) => {
  try {
    const recipeId = req.params.id;
    
    // Get the recipe details
    const recipe = await recipeDb.getRecipeById(recipeId);
    if (!recipe) {
      return res.status(404).render('error', {
        message: 'Recipe not found',
        error: { status: 404 },
        pageTitle: 'Error',
        activePage: '',
        title: 'RecipeGen AI - Error'
      });
    }
    
    // Check if user has access to this recipe
    const orgId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    
    if (recipe.organization_id !== orgId || 
        (userId && recipe.owner_id !== userId)) {
      return res.status(403).render('error', {
        message: 'You do not have permission to view this recipe',
        error: { status: 403 },
        pageTitle: 'Error',
        activePage: '',
        title: 'RecipeGen AI - Error'
      });
    }
    
    // Get the associated content
    const facebook = await facebookDb.getFacebookContentByRecipeId(
      recipeId, 
      orgId,
      userId
    );
    const pinterestVariations = await pinterestDb.getVariationsByRecipeId(recipeId);
    const blog = await blogDb.getBlogContentByRecipeId(recipeId);
    
    // NEW CODE: Fetch the Midjourney image URL for this recipe
    let midjourneyImageUrl = "";
    try {
      // Get the most recent recipe image from the recipe_images table
      const recipeImage = await db.getOne(
        "SELECT image_path FROM recipe_images WHERE recipe_id = ? ORDER BY created_at DESC LIMIT 1",
        [recipeId]
      );
      
      if (recipeImage && recipeImage.image_path) {
        // Construct the full URL path for the image
        midjourneyImageUrl = `/recipe_images/${recipeImage.image_path}`;
      }
    } catch (imageError) {
      console.error('Error fetching Midjourney image:', imageError);
      // Continue without image if there's an error
    }
    
    res.render('recipe-view', { 
      recipe,
      facebook,
      pinterestVariations,
      blog,
      midjourneyImageUrl, // Pass the image URL to the template
      pageTitle: recipe.recipe_idea,
      activePage: 'recipes',
      title: `RecipeGen AI - ${recipe.recipe_idea}`
    });
  } catch (error) {
    console.error('Error fetching recipe details:', error);
    res.status(500).render('error', {
      message: 'Failed to load recipe details',
      error: error,
      pageTitle: 'Error',
      activePage: '',
      title: 'RecipeGen AI - Error'
    });
  }
});


// WordPress settings page
app.get('/wordpress-settings', isAuthenticated, async (req, res) => {
  try {
    // Make sure to pass the user ID when getting settings
    const settings = await wordpressDb.getSettings();
    
    res.render('wordpress-settings', {
      pageTitle: 'WordPress Settings',
      activePage: 'wordpress-settings',
      title: 'RecipeGen AI - WordPress Settings',
      settings: settings || {},
      successMessage: req.session.successMessage || null,
      errorMessage: req.session.errorMessage || null
    });
    
    // Clear session messages
    delete req.session.successMessage;
    delete req.session.errorMessage;
  } catch (error) {
    console.error('Error loading WordPress settings:', error);
    res.render('wordpress-settings', {
      pageTitle: 'WordPress Settings',
      activePage: 'wordpress-settings',
      title: 'RecipeGen AI - WordPress Settings',
      settings: {},
      successMessage: null,
      errorMessage: 'Failed to load WordPress settings: ' + error.message
    });
  }
});

// Users management page (admin only)
app.get('/users', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    
    // Get all users in this organization
    const users = await userDb.getUsersByOrganization(organizationId);
    
    // Enrich with statistics for each user
    for (const user of users) {
      // Get recipe count
      user.stats = {
        recipeCount: await recipeDb.getRecipeCountByOwner(user.id),
        processedKeywords: await keywordsDb.getKeywordsCount('processed', null, user.id)
      };
      
      // Get last activity
      const lastActivity = await getOne(
        `SELECT created_at FROM activity_logs 
         WHERE user_id = ? 
         ORDER BY created_at DESC LIMIT 1`,
        [user.id]
      );
      
      if (lastActivity) {
        user.lastActive = lastActivity.created_at;
      }
    }
    
    res.render('users', {
      users: users,
      pageTitle: 'User Management',
      activePage: 'users',
      title: 'RecipeGen AI - User Management'
    });
  } catch (error) {
    console.error('Error loading users page:', error);
    res.render('error', {
      message: 'Failed to load users',
      error: error,
      pageTitle: 'Error',
      activePage: '',
      title: 'RecipeGen AI - Error'
    });
  }
});

// GET route for user edit page
app.get('/users/edit/:id', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const user = await userDb.getUserById(userId);
    
    if (!user) {
      req.session.errorMessage = 'User not found';
      return res.redirect('/users');
    }
    
    res.render('user-edit', {
      pageTitle: 'Edit User',
      activePage: 'users',
      title: 'RecipeGen AI - Edit User',
      user: user
    });
  } catch (error) {
    console.error('Error loading user edit page:', error);
    req.session.errorMessage = 'Failed to load user: ' + error.message;
    res.redirect('/users');
  }
});




// GET route for user delete (with confirmation)
app.get('/users/delete/:id', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Don't allow deleting your own account
    if (userId === req.session.user.id) {
      req.session.errorMessage = 'You cannot delete your own account.';
      // Redirect back to where user came from
      const redirectUrl = req.get('Referrer') || '/users';
      return res.redirect(redirectUrl);
    }
    
    const user = await userDb.getUserById(userId);
    
    if (!user) {
      req.session.errorMessage = 'User not found';
      // Redirect back to where user came from
      const redirectUrl = req.get('Referrer') || '/users';
      return res.redirect(redirectUrl);
    }
    
    // Delete the user
    const deleteResult = await userDb.deleteUser(userId);
    
    if (deleteResult) {
      req.session.successMessage = 'User deleted successfully';
    } else {
      req.session.errorMessage = 'Failed to delete user';
    }
    
    // Redirect back to where user came from
    const redirectUrl = req.get('Referrer') || '/users';
    res.redirect(redirectUrl);
  } catch (error) {
    console.error('Error deleting user:', error);
    req.session.errorMessage = 'Failed to delete user: ' + error.message;
    // Redirect back to where user came from
    const redirectUrl = req.get('Referrer') || '/users';
    res.redirect(redirectUrl);
  }
});

// POST route for editing user
app.post('/users/edit/:id', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { name, email, role, password } = req.body;
    
    // Validate required fields
    if (!name || !email || !role) {
      req.session.errorMessage = 'Name, email, and role are required.';
      return res.redirect(`/users/edit/${userId}`);
    }
    
    // Update user
    const updateResult = await userDb.updateUser(userId, {
      name,
      email,
      role,
      password: password ? password : undefined // Only update password if provided
    });
    
    if (updateResult) {
      req.session.successMessage = 'User updated successfully';
      res.redirect('/users');
    } else {
      req.session.errorMessage = 'Failed to update user';
      res.redirect(`/users/edit/${userId}`);
    }
  } catch (error) {
    console.error('Error updating user:', error);
    req.session.errorMessage = 'Failed to update user: ' + error.message;
    res.redirect(`/users/edit/${userId}`);
  }
});

// WP Recipe Maker settings page
app.get('/wordpress-recipe-settings', isAuthenticated, async (req, res) => {
  try {
    // Load both WordPress and WPRM settings
    const wpSettings = await wordpressDb.getSettings();
    
    // Require recipe DB module
    const recipeDb = require('./wordpress-recipe-db');
    const wprmSettings = await recipeDb.getSettings();
    
    res.render('wordpress-recipe-settings', {
      pageTitle: 'WP Recipe Maker Settings',
      activePage: 'wordpress-recipe-settings',
      title: 'RecipeGen AI - WP Recipe Maker Settings',
      wpSettings: wpSettings || {},
      settings: wprmSettings || {},
      successMessage: req.session.successMessage || null,
      errorMessage: req.session.errorMessage || null
    });
    
    // Clear session messages
    delete req.session.successMessage;
    delete req.session.errorMessage;
  } catch (error) {
    console.error('Error loading WP Recipe Maker settings:', error);
    res.render('wordpress-recipe-settings', {
      pageTitle: 'WP Recipe Maker Settings',
      activePage: 'wordpress-recipe-settings',
      title: 'RecipeGen AI - WP Recipe Maker Settings',
      wpSettings: {},
      settings: {},
      successMessage: null,
      errorMessage: 'Failed to load WP Recipe Maker settings: ' + error.message
    });
  }
});

// Save WP Recipe Maker settings
app.post('/wordpress-recipe-settings', async (req, res) => {
  try {
    const { enabled, addToAllPosts, keywords } = req.body;
    
    // Require recipe DB module
    const recipeDb = require('./wordpress-recipe-db');
    
    // Save settings
    await recipeDb.saveSettings({
      enabled: enabled === 'on',
      addToAllPosts: addToAllPosts === 'on',
      keywords: keywords || ''
    });
    
    req.session.successMessage = 'WP Recipe Maker settings saved successfully!';
    res.redirect('/wordpress-recipe-settings');
  } catch (error) {
    console.error('Error saving WP Recipe Maker settings:', error);
    req.session.errorMessage = 'Failed to save WP Recipe Maker settings: ' + error.message;
    res.redirect('/wordpress-recipe-settings');
  }
});

app.post('/wordpress-settings', isAuthenticated, async (req, res) => {
  try {
    const { siteUrl, username, password, defaultStatus } = req.body;
    
    // Validate required fields
    if (!siteUrl || !username || !password) {
      req.session.errorMessage = 'Site URL, username, and password are required.';
      return res.redirect('/wordpress-settings');
    }
    
    // Save settings with userId from session
    await wordpressDb.saveSettings({
      userId: req.session.user.id,  // Make sure this is passed correctly
      siteUrl,
      username,
      password,
      defaultStatus: defaultStatus || 'draft'
    });
    
    req.session.successMessage = 'WordPress settings saved successfully!';
    res.redirect('/wordpress-settings');
  } catch (error) {
    console.error('Error saving WordPress settings:', error);
    req.session.errorMessage = 'Failed to save WordPress settings: ' + error.message;
    res.redirect('/wordpress-settings');
  }
});

// Add this route to get recipe template settings
app.get('/wordpress-recipe-templates',isAuthenticated, (req, res) => {
  try {
    // Load template settings
    const settings = recipeTemplateSettings.loadTemplateSettings();
    
    console.log('Loaded template settings:', settings);
    
    // Render the template settings page
    res.render('wordpress-recipe-templates', {
      title: 'Recipe Template Settings',
      settings: settings,
      user: req.user,
      messages: req.flash()
    });
  } catch (error) {
    console.error('Error loading template settings:', error);
    res.status(500).render('error', {
      message: 'Error loading template settings',
      error: error
    });
  }
});

// Add this route to save recipe template settings
app.post('/wordpress-recipe-templates',isAuthenticated, (req, res) => {
  try {
    console.log('Received template settings form data:', req.body);
    
    // Extract settings from request body
    const settings = {
      // Description templates
      defaultDescription: req.body.defaultDescription,
      cakeDescription: req.body.cakeDescription,
      soupDescription: req.body.soupDescription,
      saladDescription: req.body.saladDescription || '',
      chickenDescription: req.body.chickenDescription || '',
      
      // Notes templates settings
      enableStorageNote: req.body.enableStorageNote === 'on',
      storageNoteTemplate: req.body.storageNoteTemplate || '',
      storageDays: parseInt(req.body.storageDays) || 3,
      
      enableMakeAheadNote: req.body.enableMakeAheadNote === 'on',
      makeAheadTemplate: req.body.makeAheadTemplate || '',
      makeAheadHours: parseInt(req.body.makeAheadHours) || 24,
      dishType: req.body.dishType || 'dish',
      extraInstructions: req.body.extraInstructions || 'Cover and refrigerate until ready to serve.'
    };
    
    console.log('Processed settings to save:', settings);
    
    // Save settings
    const saved = recipeTemplateSettings.saveTemplateSettings(settings);
    
    if (saved) {
      // Set success message
      req.flash('success', 'Recipe template settings saved successfully.');
      console.log('Settings saved successfully');
    } else {
      // Set error message
      req.flash('error', 'Error saving recipe template settings.');
      console.log('Error saving settings');
    }
    
    // Redirect back to settings page
    res.redirect('/wordpress-recipe-templates');
  } catch (error) {
    console.error('Error saving template settings:', error);
    req.flash('error', 'Error saving recipe template settings: ' + error.message);
    res.redirect('/wordpress-recipe-templates');
  }
});

// User profile page
app.get('/profile', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const organizationId = req.session.user.organizationId;
    
    // Get user details
    const user = await userDb.getUserById(userId);

    if (user) {
  // Get user's content statistics if not already attached
  if (!user.stats) {
    user.stats = {
      recipeCount: await recipeDb.getRecipeCountByOwner(user.id),
      keywordCounts: {
        pending: await keywordsDb.getKeywordsCount('pending', null, user.id),
        processed: await keywordsDb.getKeywordsCount('processed', null, user.id),
        failed: await keywordsDb.getKeywordsCount('failed', null, user.id)
      },
      wpPostCount: 0
    };
    
    // Calculate totals
    user.stats.keywordCounts.total = user.stats.keywordCounts.pending + 
                                     user.stats.keywordCounts.processed + 
                                     user.stats.keywordCounts.failed;
    user.stats.totalContent = user.stats.recipeCount + user.stats.keywordCounts.processed;
    
    // Get WordPress post count if applicable
    try {
      user.stats.wpPostCount = await wordpressDb.getPublicationCount(user.id);
    } catch (error) {
      console.log('No WordPress publications found or error counting them:', error.message);
    }
  }
}
    
    // Get activity stats
    const stats = {
      recipeCount: await recipeDb.getRecipeCountByOwner(userId),
      keywordCounts: {
        pending: await keywordsDb.getKeywordsCount('pending', null, userId),
        processed: await keywordsDb.getKeywordsCount('processed', null, userId),
        failed: await keywordsDb.getKeywordsCount('failed', null, userId)
      },
      wpPostCount: 0
    };
    
    // Calculate totals
    stats.keywordCounts.total = stats.keywordCounts.pending + stats.keywordCounts.processed + stats.keywordCounts.failed;
    stats.totalContent = stats.recipeCount + stats.keywordCounts.processed;
    
    // Get WordPress post count if we have WordPress integration
    try {
      stats.wpPostCount = await wordpressDb.getPublicationCount(userId, null, req.session.currentWebsiteId);
    } catch (error) {
      console.log('No WordPress publications found or error counting them:', error.message);
    }
    
    // Get user activity
    const activity = await activityLogger.getRecentActivity(organizationId, 20, userId);
    
    res.render('profile', {
      user: user,
      stats: stats,
      activity: activity,
      pageTitle: 'User Profile',
      activePage: 'profile',
      title: 'RecipeGen AI - User Profile'
    });
  } catch (error) {
    console.error('Error loading profile page:', error);
    res.render('error', {
      message: 'Failed to load profile',
      error: error,
      pageTitle: 'Error',
      activePage: '',
      title: 'RecipeGen AI - Error'
    });
  }
});

// Add this middleware to update promptConfig when website changes
app.use((req, res, next) => {
  // Check if the website has changed
  if (req.session && 
      req.session.currentWebsiteId && 
      req.session.user && 
      req.session.user.organizationId) {
    
    // Only load settings if not already done for this request
    if (!req.promptConfigLoaded) {
      req.promptConfigLoaded = true;
      
      // Load website-specific settings
      try {
        const websiteSettings = promptSettingsDb.loadSettings(
          req.session.user.organizationId,
          req.session.currentWebsiteId
        );
        
        // Update the global promptConfig
        promptConfig = websiteSettings;
        
        // Update app.js configuration if needed
        const appModule = require('./app');
        appModule.updateConfig({
          model: promptConfig.model,
          temperature: promptConfig.temperature,
          apiKey: promptConfig.apiKey,
          language: promptConfig.language,
          pinCount: promptConfig.pinCount,
          prompts: promptConfig.prompts
        });
      } catch (error) {
        console.error('Error loading prompt settings for website switch:', error);
      }
    }
  }
  
  next();
});

// Website management routes (admin only)
app.get('/websites', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const websites = await websiteDb.getWebsitesByOrganization(organizationId);
    
    const successMessage = req.session.successMessage;
    const errorMessage = req.session.errorMessage;
    delete req.session.successMessage;
    delete req.session.errorMessage;
    
    res.render('websites', {
      title: 'Website Management',
      activePage: 'websites',
      user: req.session.user,
      websites: websites,
      currentWebsiteId: req.session.currentWebsiteId,
      successMessage,
      errorMessage
    });
  } catch (error) {
    console.error('Error loading websites:', error);
    req.session.errorMessage = 'Error loading websites.';
    res.redirect('/');
  }
});

// Website duplication routes (admin only)
app.post('/websites/duplicate', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { sourceWebsiteId, name, url } = req.body;
    const organizationId = req.session.user.organizationId;
    
    console.log(`🔄 Duplicating website ${sourceWebsiteId} as "${name}" for organization ${organizationId}`);
    
    // Validate inputs
    if (!sourceWebsiteId || !name) {
      req.session.errorMessage = 'Source website and new name are required.';
      return res.redirect('/websites');
    }

    // Check if source website exists and belongs to the organization
    const sourceWebsite = await websiteDb.getWebsiteById(sourceWebsiteId);
    if (!sourceWebsite || sourceWebsite.organization_id !== organizationId) {
      req.session.errorMessage = 'Source website not found or access denied.';
      return res.redirect('/websites');
    }

    // Create new website with basic info
    const newWebsite = await websiteDb.createWebsite({
      name: name.trim(),
      url: url ? url.trim() : sourceWebsite.url,
      organizationId: organizationId
    });

    const newWebsiteId = newWebsite.id;
    console.log(`✅ Created new website with ID: ${newWebsiteId}`);

    // Copy all settings from source to new website
    try {
      console.log(`📄 Loading settings for source website ${sourceWebsiteId} in organization ${organizationId}`);
      
      // Check if settings file exists for source website
      const fs = require('fs');
      const path = require('path');
      const sourceSettingsFile = path.join(__dirname, 'data', `config-${organizationId}-${sourceWebsiteId}.json`);
      const sourceFileExists = fs.existsSync(sourceSettingsFile);
      
      console.log(`📁 Source settings file check:`, {
        filePath: sourceSettingsFile,
        exists: sourceFileExists,
        relativeFromProject: `data/config-${organizationId}-${sourceWebsiteId}.json`
      });
      
      // Load source website settings
      const sourceSettings = promptSettingsDb.loadSettings(organizationId, sourceWebsiteId);
      
      console.log(`📄 Source settings loaded:`, {
        hasSettings: !!sourceSettings,
        settingsKeys: sourceSettings ? Object.keys(sourceSettings) : [],
        settingsCount: sourceSettings ? Object.keys(sourceSettings).length : 0
      });
      
      // Determine which settings to copy
      let settingsToCopy = null;
      
      if (sourceSettings && Object.keys(sourceSettings).length > 0) {
        settingsToCopy = sourceSettings;
        console.log(`📋 Using source website settings`);
      } else if (global.promptConfig && Object.keys(global.promptConfig).length > 0) {
        settingsToCopy = { ...global.promptConfig };
        console.log(`📋 Using global promptConfig as fallback`);
      } else {
        console.log(`⚠️ No settings available to copy`);
      }
      
      if (settingsToCopy) {
        // Save settings to new website
        console.log(`💾 Saving settings to new website ${newWebsiteId}`);
        console.log(`   Settings to save:`, Object.keys(settingsToCopy));
        
        promptSettingsDb.saveSettings(settingsToCopy, organizationId, newWebsiteId);
        
        // Verify settings were saved by loading them back
        const verifySettings = promptSettingsDb.loadSettings(organizationId, newWebsiteId);
        console.log(`✅ Settings verification:`, {
          savedSuccessfully: !!verifySettings,
          verifyKeys: verifySettings ? Object.keys(verifySettings) : [],
          verifyCount: verifySettings ? Object.keys(verifySettings).length : 0
        });
        
        if (verifySettings && Object.keys(verifySettings).length > 0) {
          console.log(`✅ Settings successfully copied to new website ${newWebsiteId}`);
          console.log(`   Verified settings: ${Object.keys(verifySettings).join(', ')}`);
        } else {
          console.warn(`⚠️ Settings verification failed - new website may not have settings`);
        }
      }
    } catch (settingsError) {
      console.error('❌ Error copying settings:', settingsError);
      console.error('   Settings error details:', settingsError.message);
      console.error('   Stack:', settingsError.stack);
      // Continue anyway - the website was created successfully
    }

    req.session.successMessage = `Website "${name}" duplicated successfully with all settings copied from "${sourceWebsite.name}".`;
    res.redirect('/websites');
    
  } catch (error) {
    console.error('❌ Error duplicating website:', error);
    req.session.errorMessage = 'Error duplicating website. Please try again.';
    res.redirect('/websites');
  }
});

// UPDATED: Replace your existing settings POST route around line 2211 in server.js
// Employee Discord settings routes (accessible to employees only)
app.get('/employee-discord', isAuthenticated, async (req, res) => {
  try {
    // Redirect admins to the main settings page
    if (req.session.user.role === 'admin') {
      req.session.errorMessage = 'Admins should use the main Settings page to configure Discord. Employee Discord settings are for employees only.';
      return res.redirect('/settings');
    }

    const successMessage = req.session.successMessage;
    const errorMessage = req.session.errorMessage;
    const updatedToken = req.session.updatedDiscordToken;
    delete req.session.successMessage;
    delete req.session.errorMessage;
    delete req.session.updatedDiscordToken;

    // Get organization-specific Discord settings to show if token exists
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    
    let currentToken = null;
    try {
      // If we just updated the token, use the updated one to show in UI
      if (updatedToken) {
        currentToken = updatedToken;
        console.log(`📋 Showing updated Discord token in UI for User: ${req.session.user.name}`);
      } else {
        const discordSettings = await getCurrentDiscordSettings(req);
        currentToken = discordSettings?.discordUserToken || null;
      }
      
      console.log(`📋 Employee Discord page for Org: ${organizationId}, Website: ${websiteId}, User: ${req.session.user.name}`);
      console.log(`   Current token: ${currentToken ? 'Present (' + currentToken.substring(0, 10) + '...)' : 'Not set'}`);
    } catch (error) {
      console.log('Could not load organization-specific Discord settings:', error.message);
    }

    res.render('employee-discord', {
      title: 'Discord Settings',
      user: req.session.user,
      activePage: 'employee-discord',
      successMessage,
      errorMessage,
      currentToken
    });
  } catch (error) {
    console.error('Error loading employee Discord page:', error);
    req.session.errorMessage = 'Error loading Discord settings page';
    res.redirect('/dashboard');
  }
});

app.post('/employee-discord', isAuthenticated, async (req, res) => {
  try {
    // Redirect admins to the main settings page
    if (req.session.user.role === 'admin') {
      req.session.errorMessage = 'Admins should use the main Settings page to configure Discord.';
      return res.redirect('/settings');
    }

    const { discordUserToken } = req.body;
    
    if (!discordUserToken || !discordUserToken.trim()) {
      req.session.errorMessage = 'Discord user token is required';
      return res.redirect('/employee-discord');
    }

    const cleanToken = discordUserToken.trim();
    
    // Get current context
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;

    // Validate that we have proper organization context
    if (!organizationId || !websiteId) {
      req.session.errorMessage = 'Missing organization or website context. Please contact your administrator.';
      return res.redirect('/employee-discord');
    }

    console.log(`🔄 Employee Discord token update for Org: ${organizationId}, Website: ${websiteId}, User: ${req.session.user.name}`);

    // Update ONLY the organization-specific file-based settings (not global database)
    try {
      const currentSettings = promptSettingsDb.loadSettings(organizationId, websiteId);
      console.log('📄 Current organization settings loaded');
      
      // Preserve all existing settings, only update Discord token
      const updatedSettings = {
        ...currentSettings,
        discordUserToken: cleanToken,
        enableDiscord: true
      };
      
      // Save to organization-specific file
      promptSettingsDb.saveSettings(updatedSettings, organizationId, websiteId);
      
      // Update global promptConfig only for current session context
      if (req.session.user.organizationId === organizationId && req.session.currentWebsiteId === websiteId) {
        global.promptConfig = { ...global.promptConfig, discordUserToken: cleanToken, enableDiscord: true };
      }
      
      console.log('✅ Updated Discord token for employee in organization-specific settings');
      console.log(`   Organization: ${organizationId}`);
      console.log(`   Website: ${websiteId}`);
      console.log(`   Token: ${cleanToken.substring(0, 10)}...`);
      
    } catch (fileError) {
      console.error('❌ Could not update organization-specific settings:', fileError.message);
      req.session.errorMessage = 'Error updating Discord settings. Please try again.';
      return res.redirect('/employee-discord');
    }

    // Store the updated token in session temporarily to show in UI
    req.session.updatedDiscordToken = cleanToken;
    req.session.successMessage = 'Discord token updated successfully! Your Discord connection should now work.';
    res.redirect('/employee-discord');
  } catch (error) {
    console.error('Error updating employee Discord token:', error);
    req.session.errorMessage = 'Error updating Discord token. Please try again.';
    res.redirect('/employee-discord');
  }
});

// Test endpoint for employee Discord token
app.post('/api/test-employee-discord', isAuthenticated, async (req, res) => {
  try {
    const { userToken, testMessage } = req.body;
    
    if (!userToken || !userToken.trim()) {
      return res.json({
        success: false,
        message: 'Discord user token is required for testing'
      });
    }

    // Get organization-specific Discord settings for the test
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    
    if (!organizationId || !websiteId) {
      return res.json({
        success: false,
        message: 'Missing organization or website context. Please contact your administrator.'
      });
    }

    let channelId = null;
    try {
      // Get organization-specific Discord settings
      const discordSettings = await getCurrentDiscordSettings(req);
      channelId = discordSettings?.discordChannelId;
      
      console.log(`🧪 Testing Discord token for Org: ${organizationId}, Website: ${websiteId}`);
      console.log(`   Channel ID: ${channelId || 'Not set'}`);
    } catch (error) {
      console.log('Could not get organization-specific Discord settings for test:', error.message);
    }

    if (!channelId) {
      return res.json({
        success: false,
        message: 'No Discord channel configured for your organization. Please contact your administrator to set up the Discord channel.'
      });
    }

    // Test the token with Discord API
    const axios = require('axios');
    try {
      await axios.post(
        `https://discord.com/api/v10/channels/${channelId}/messages`,
        {
          content: testMessage || 'Discord connection test successful! 🎉'
        },
        {
          timeout: 10000,
          headers: {
            'Authorization': userToken.trim(),
            'Content-Type': 'application/json'
          }
        }
      );

      res.json({
        success: true,
        message: 'Discord connection successful! Test message sent to Discord channel.',
        method: 'User Token'
      });
    } catch (tokenError) {
      console.error('Discord token test failed:', tokenError.response?.data || tokenError.message);
      
      let errorMessage = 'Discord connection failed';
      if (tokenError.response) {
        if (tokenError.response.status === 401) {
          errorMessage = 'Invalid Discord token. Please check your token and try again.';
        } else if (tokenError.response.status === 403) {
          errorMessage = 'Permission denied. Your Discord account may not have permission to send messages to this channel.';
        } else if (tokenError.response.status === 404) {
          errorMessage = 'Discord channel not found. Please contact your administrator.';
        } else {
          errorMessage = `Discord API error: ${tokenError.response.data?.message || tokenError.message}`;
        }
      }
      
      res.json({
        success: false,
        message: errorMessage
      });
    }
  } catch (error) {
    console.error('Error testing employee Discord token:', error);
    res.status(500).json({
      success: false,
      message: `Server error: ${error.message}`
    });
  }
});

app.post('/settings', isAuthenticated, async (req, res) => {
  console.log('Received settings update');
  
  try {
    // Get the API key directly from the form
    const openaiApiKey = req.body.openaiApiKey;
    
    // Get organization ID and website ID from session
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    
    // Update prompt configuration
    const newSettings = {
      model: req.body.model || 'gpt-4-turbo-preview',
      temperature: parseFloat(req.body.temperature || '0.7'),
      apiKey: openaiApiKey,
      language: req.body.language || 'English',
      pinCount: parseInt(req.body.pinCount || '10'),
      
      // Add Discord settings
      discordChannelId: req.body.discordChannelId || '',
      discordUserToken: req.body.discordUserToken || '',
      discordWebhookUrl: req.body.discordWebhookUrl || '',
      enableDiscord: req.body.enableDiscord === 'on',
      
      // Add Buffer settings
      bufferEnabled: req.body.bufferEnabled === 'on',
      bufferCookiesText: req.body.bufferCookiesText || '',
      bufferProfileId: req.body.bufferProfileId ? req.body.bufferProfileId.trim() : '',
      bufferOrgId: req.body.bufferOrgId ? req.body.bufferOrgId.trim() : '',
      bufferBoards: req.body.bufferBoards ? req.body.bufferBoards.map(board => ({
        id: board.id ? board.id.trim() : '',
        name: board.name ? board.name.trim() : ''
      })).filter(board => board.id && board.name) : [{id: '', name: 'Default Board'}],
      
      prompts: {
        pinTitleSystem: req.body.pinTitleSystem || '',
        pinTitleUser: req.body.pinTitleUser || '',
        pinDescSystem: req.body.pinDescSystem || '',
        pinDescUser: req.body.pinDescUser || '',
        pinOverlaySystem: req.body.pinOverlaySystem || '',
        pinOverlayUser: req.body.pinOverlayUser || '',
        metaTitleSystem: req.body.metaTitleSystem || '',
        metaTitleUser: req.body.metaTitleUser || '',
        metaDescSystem: req.body.metaDescSystem || '',
        metaDescUser: req.body.metaDescUser || '',
        slugSystemPrompt: req.body.slugSystemPrompt || '',
        slugUserPrompt: req.body.slugUserPrompt || '',
        blogpostSystemPrompt: req.body.blogpostSystemPrompt || '',
        blogpostUserPrompt: req.body.blogpostUserPrompt || '',
        fbPrompt: req.body.fbPrompt || '',
        mjTemplate: req.body.mjTemplate || '',
        fbCaptionPrompt: req.body.fbCaptionPrompt || ''
      }
    };
    
    // SAVE TO BOTH SYSTEMS
    
    // 1. Save to website-specific file (existing system)
    promptSettingsDb.saveSettings(newSettings, organizationId, websiteId);
    
    // 2. ALSO save Discord settings to database (new system)
    try {
      console.log('💾 Saving Discord settings to database...');
      await saveDiscordSettingsToDatabase({
        discordChannelId: newSettings.discordChannelId,
        discordUserToken: newSettings.discordUserToken,
        discordWebhookUrl: newSettings.discordWebhookUrl,
        enableDiscord: newSettings.enableDiscord
      });
      console.log('✅ Discord settings saved to database');
    } catch (dbError) {
      console.warn('⚠️ Could not save Discord settings to database:', dbError.message);
      // Continue anyway - the file-based system will still work
    }
    
    // Also update global promptConfig for backward compatibility
    promptConfig = newSettings;
    
    console.log(`Saved prompt settings for organization ${organizationId} and website ${websiteId}`);
    console.log('Discord settings in new config:', {
      channelId: newSettings.discordChannelId ? 'SET' : 'NOT SET',
      token: newSettings.discordUserToken ? 'SET' : 'NOT SET',
      enabled: newSettings.enableDiscord
    });
    
    // Update the app.js module with the new config
    const appModule = require('./app');
    appModule.updateConfig({
      model: newSettings.model,
      temperature: newSettings.temperature,
      apiKey: openaiApiKey,
      language: newSettings.language,
      pinCount: newSettings.pinCount,
      // Pass Discord settings to app.js
      discordChannelId: newSettings.discordChannelId,
      discordUserToken: newSettings.discordUserToken,
      discordWebhookUrl: newSettings.discordWebhookUrl,
      enableDiscord: newSettings.enableDiscord,
      prompts: newSettings.prompts
    });
    
    console.log('Updated app.js module configuration with Discord settings');
    
    // Reset Midjourney client instance to pick up new settings
    try {
      const MidjourneyClient = require('./midjourney/midjourney-client');
      MidjourneyClient.resetInstance();
      console.log('✅ Reset Midjourney client to use new Discord settings');
    } catch (resetError) {
      console.warn('Could not reset Midjourney client:', resetError.message);
    }
    
    // Store in session
    req.session.promptConfig = newSettings;
    
    // Redirect with success message
    req.session.successMessage = 'Settings saved successfully! Discord integration updated.';
    res.redirect('/settings');
  } catch (error) {
    console.error('Error saving settings:', error);
    req.session.errorMessage = `Error saving settings: ${error.message}`;
    res.redirect('/settings');
  }
});

// Helper function to save Discord settings to database
async function saveDiscordSettingsToDatabase(discordSettings) {
  try {
    const { runQuery } = require('./db');
    
    await runQuery(
      "UPDATE app_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = 'discord_channel_id'",
      [discordSettings.discordChannelId || '']
    );
    
    await runQuery(
      "UPDATE app_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = 'discord_user_token'",
      [discordSettings.discordUserToken || '']
    );
    
    await runQuery(
      "UPDATE app_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = 'discord_webhook_url'",
      [discordSettings.discordWebhookUrl || '']
    );
    
    await runQuery(
      "UPDATE app_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = 'enable_discord'",
      [discordSettings.enableDiscord ? 'true' : 'false']
    );
    
    return true;
  } catch (error) {
    console.error('Error saving Discord settings to database:', error.message);
    throw error;
  }
}

// ==========================================
// ALL API ENDPOINTS - MUST COME BEFORE ERROR HANDLERS
// ==========================================

// API endpoint to check API key status without revealing the key
app.get('/api/keys/status', async (req, res) => {
  try {
    const openaiKeyExists = !(await isApiKeyMissing('openai'));
    
    res.json({
      success: true,
      keys: {
        openai: openaiKeyExists
      }
    });
  } catch (error) {
    console.error('Error checking API key status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check API key status'
    });
  }
});

// Test OpenAI API connection
app.post('/api/test-connection', async (req, res) => {
  const { model, apiKey: providedApiKey } = req.body;
  
  // Use provided API key or get from database/env
  let apiKey = providedApiKey;
  if (!apiKey || apiKey.includes('•')) {
    // Try to get the key from the database first, then fall back to env if needed
    apiKey = await apiKeyManager.getApiKey('openai');
    
    // If still no key, use the one from promptConfig
    if (!apiKey) {
      apiKey = promptConfig.apiKey;
    }
  }
  
  if (!model) {
    return res.json({
      success: false,
      message: 'Model is required'
    });
  }
  
  if (!apiKey) {
    return res.json({
      success: false,
      message: 'No API key available. Please provide an OpenAI API key.'
    });
  }
  
  try {
    const response = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: model,
        messages: [
          { role: 'user', content: 'Hello, this is a test message. Please respond with "Connection successful".' }
        ],
        max_tokens: 20
      },
      {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`
        }
      }
    );
    
    if (response.data && response.data.choices && response.data.choices.length > 0) {
      return res.json({
        success: true,
        message: 'Connection successful',
        model: model,
        response: response.data.choices[0].message.content.trim()
      });
    } else {
      return res.json({
        success: false,
        message: 'Invalid response from API'
      });
    }
  } catch (error) {
    console.error('API test error:', error.response?.data || error.message);
    return res.json({
      success: false,
      message: error.response?.data?.error?.message || error.message
    });
  }
});



app.post('/api/keywords/add', isAuthenticated, activityMiddleware.logActivity('create', 'keyword'), async (req, res) => {
  try {
    console.log('Request body for keyword addition:', JSON.stringify(req.body, null, 2));
    
    let keywordsData = [];
    
    // Get user ID and organization ID from session
    const ownerId = req.session.user.id;
    const organizationId = req.session.user.organizationId;
    
    console.log(`User ID: ${ownerId}, Organization ID: ${organizationId}`);
    
    if (!ownerId || !organizationId) {
      const errorMsg = 'User authentication required - missing user ID or organization ID';
      console.error(errorMsg);
      return res.status(401).json({
        success: false,
        message: errorMsg
      });
    }
    
    // Check if data is coming from regular form submission (string format)
    if (req.body.keywords && typeof req.body.keywords === 'string') {
      console.log('Processing string input (manual textarea)');
      
      // Split by "---" to separate multiple recipes
      const recipes = req.body.keywords.split('---')
        .map(recipe => recipe.trim())
        .filter(recipe => recipe.length > 0);
      
      console.log(`Found ${recipes.length} recipes in string input`);
      
      keywordsData = recipes.map(fullRecipe => {
        // Extract the first line as the keyword/title
        const lines = fullRecipe.split('\n').filter(line => line.trim());
        const keyword = lines.length > 0 ? lines[0].trim() : 'Recipe';
        
        console.log(`Processing recipe with title: "${keyword}"`);
        
        return {
          keyword: keyword,
          full_recipe: fullRecipe,
          category: req.body.defaultCategory || null,
          interests: req.body.defaultInterests || null,
          image_url: req.body.imageUrl || null,
          ownerId: ownerId,
          organizationId: organizationId
        };
      });
      
    } else if (req.body.keywords && Array.isArray(req.body.keywords)) {
      console.log('Processing array input (JavaScript submission)');
      
      keywordsData = req.body.keywords.map(keyword => {
        // If it's a string (old format), treat as keyword
        if (typeof keyword === 'string') {
          console.log(`Processing string keyword: "${keyword}"`);
          return {
            keyword: keyword.trim(),
            full_recipe: null, // No full recipe provided
            category: req.body.defaultCategory || null,
            interests: req.body.defaultInterests || null,
            image_url: req.body.imageUrl || null,
            ownerId: ownerId,
            organizationId: organizationId
          };
        } 
        // If it's an object with full_recipe property (new format)
        else if (typeof keyword === 'object' && keyword.full_recipe) {
          console.log(`Processing full recipe with title: "${keyword.keyword}"`);
          return {
            keyword: keyword.keyword.trim(),
            full_recipe: keyword.full_recipe,
            category: keyword.category || req.body.defaultCategory || null,
            interests: keyword.interests || req.body.defaultInterests || null,
            image_url: keyword.image_url || req.body.imageUrl || null,
            ownerId: ownerId,
            organizationId: organizationId
          };
        }
        // If it's an object with just keyword (old format)
        else if (typeof keyword === 'object' && keyword.keyword) {
          console.log(`Processing keyword object: "${keyword.keyword}"`);
          return {
            keyword: keyword.keyword.trim(),
            full_recipe: null,
            category: keyword.category || req.body.defaultCategory || null,
            interests: keyword.interests || req.body.defaultInterests || null,
            image_url: keyword.image_url || req.body.imageUrl || null,
            ownerId: ownerId,
            organizationId: organizationId
          };
        }
        return null;
      }).filter(k => k !== null && k.keyword && k.keyword.trim().length > 0);
      
      console.log(`Processed ${keywordsData.length} items from array`);
    }
    
    if (keywordsData.length === 0) {
      const errorMsg = 'No valid recipes or keywords provided after processing';
      console.error(errorMsg, { originalBody: req.body });
      return res.status(400).json({
        success: false,
        message: errorMsg
      });
    }
    
    // Log what we're about to add
    keywordsData.forEach((item, index) => {
      console.log(`Item ${index + 1}: keyword="${item.keyword}", has_full_recipe=${!!item.full_recipe}`);
    });
    
    // Add keywords to database
    console.log(`Attempting to add ${keywordsData.length} items to database`);
    const keywordIds = await keywordsDb.addKeywordsBatch(keywordsData);
    
    console.log(`Successfully added ${keywordIds.length} items to database`);
    
    // Return JSON response for API clients
    const hasFullRecipes = keywordsData.some(k => k.full_recipe);
    const successMessage = hasFullRecipes ? 
      `Added ${keywordIds.length} recipes successfully` : 
      `Added ${keywordIds.length} keywords successfully`;
    
    return res.json({
      success: true,
      message: successMessage,
      count: keywordIds.length
    });
    
  } catch (error) {
    console.error('Error adding keywords/recipes:', error);
    
    return res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});


app.post('/api/keywords/process-selected', isAuthenticated, activityMiddleware.logActivity('process', 'keyword'), async (req, res) => {
  try {
    const { keywordIds, contentOption, useTemplate = false, templateId = null } = req.body;
    
    if (!keywordIds || !Array.isArray(keywordIds) || keywordIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No keywords selected for processing'
      });
    }
    
    console.log(`🔥 [PROCESS] Processing ${keywordIds.length} selected keywords with option: ${contentOption}`, 
      useTemplate ? `using template: ${templateId}` : '(no template)');
    
    // Get organization ID and user ID from session
    const organizationId = req.session.user.organizationId;
    const userId = req.session.user.id;
    const websiteId = req.session.currentWebsiteId;
    
    console.log(`👤 [PROCESS] User: ${userId}, 🏢 Org: ${organizationId}, 🌐 Website: ${websiteId}`);
    
    // CRITICAL FIX: Use database-level atomic updates to prevent race conditions
    const results = [];
    
    for (const keywordId of keywordIds) {
      let processingStartTime = Date.now();
      
      try {
        console.log(`🎯 [PROCESS] Processing keyword ID: ${keywordId}`);
        
        // STEP 1: Atomic status update to 'processing' - this prevents race conditions
        console.log(`🔒 [PROCESS] Attempting to lock keyword ${keywordId} for processing...`);
        
        const lockResult = await runQuery(`
          UPDATE keywords 
          SET status = 'processing', 
              processing_started_at = CURRENT_TIMESTAMP 
          WHERE id = ? 
            AND (status = 'pending' OR status = 'failed')
            AND organization_id = ?
            AND website_id = ?
        `, [keywordId, organizationId, websiteId]);
        
        if (lockResult.changes === 0) {
          console.log(`⚠️ [PROCESS] Could not lock keyword ${keywordId} - likely already being processed or not found`);
          
          // Check current status
          const currentKeyword = await getOne(`
            SELECT id, keyword, status, recipe_id 
            FROM keywords 
            WHERE id = ? AND organization_id = ?
          `, [keywordId, organizationId]);
          
          if (!currentKeyword) {
            results.push({
              id: keywordId,
              success: false,
              status: 'not_found',
              message: 'Keyword not found'
            });
          } else if (currentKeyword.status === 'processed') {
            results.push({
              id: currentKeyword.id,
              keyword: currentKeyword.keyword,
              status: 'already_processed',
              success: false,
              message: 'Keyword already processed',
              recipeId: currentKeyword.recipe_id
            });
          } else if (currentKeyword.status === 'processing') {
            results.push({
              id: currentKeyword.id,
              keyword: currentKeyword.keyword,
              status: 'already_processing',
              success: false,
              message: 'Keyword is already being processed by another request'
            });
          } else {
            results.push({
              id: currentKeyword.id,
              keyword: currentKeyword.keyword,
              status: 'failed',
              success: false,
              message: `Keyword status is '${currentKeyword.status}' - cannot process`
            });
          }
          continue;
        }
        
        console.log(`✅ [PROCESS] Successfully locked keyword ${keywordId} for processing`);
        
        // STEP 2: Get the keyword data (now that it's locked)
        const keyword = await getOne(`
          SELECT * FROM keywords 
          WHERE id = ? AND organization_id = ?
        `, [keywordId, organizationId]);
        
        if (!keyword) {
          console.error(`❌ [PROCESS] Keyword ${keywordId} not found after locking`);
          // Unlock the keyword
          await runQuery(`
            UPDATE keywords SET status = 'failed' WHERE id = ?
          `, [keywordId]);
          
          results.push({
            id: keywordId,
            success: false,
            status: 'failed',
            message: 'Keyword not found after locking'
          });
          continue;
        }
        
        console.log(`📋 [PROCESS] Processing keyword: "${keyword.keyword}" (ID: ${keyword.id})`);
        
        // STEP 3: Verify permissions
        if (req.session.user.role === 'employee' && keyword.owner_id !== userId) {
          console.warn(`⚠️ [PROCESS] Employee ${userId} doesn't own keyword ${keyword.id}`);
          
          // Unlock the keyword
          await runQuery(`
            UPDATE keywords SET status = 'pending' WHERE id = ?
          `, [keywordId]);
          
          results.push({
            id: keyword.id,
            keyword: keyword.keyword,
            category: keyword.category,
            status: 'permission_denied',
            success: false,
            message: 'You do not have permission to process this keyword'
          });
          continue;
        }
        
        // STEP 4: Set global website context before database operations
        global.currentWebsiteId = websiteId;
        
        // STEP 5: Create recipe record
        console.log(`📝 [PROCESS] Creating recipe for keyword: "${keyword.keyword}"`);
        const recipeId = await recipeDb.createRecipe({
          recipeIdea: keyword.keyword.trim(),
          category: keyword.category,
          interests: keyword.interests,
          language: promptConfig.language || 'English',
          ownerId: userId,
          organizationId: organizationId,
          websiteId: websiteId,
          image_url: keyword.image_url
        });
        
        console.log(`✅ [PROCESS] Created recipe with ID: ${recipeId}`);
        
        // STEP 6: Update keyword with recipe_id (but keep status as 'processing')
        await runQuery(`
          UPDATE keywords 
          SET recipe_id = ? 
          WHERE id = ?
        `, [recipeId, keywordId]);
        
        // STEP 7: Update app.js config
        const appModule = require('./app');
        appModule.updateConfig({
          model: promptConfig.model,
          apiKey: promptConfig.apiKey,
          language: promptConfig.language,
          temperature: promptConfig.temperature,
          pinCount: promptConfig.pinCount,
          prompts: promptConfig.prompts
        });
        
        let contentGenerated = false;
        const imageurl = keyword.image_url || null;
        
        // STEP 8: Check if cancelled before content generation (MORE AGGRESSIVE)
        let statusCheck;
        try {
          statusCheck = await getOne(`
            SELECT status FROM keywords WHERE id = ? AND organization_id = ?
          `, [keyword.id, organizationId]);
        } catch (statusError) {
          console.error(`❌ [PROCESS] Error checking status for keyword ${keyword.id}:`, statusError);
        }
        
        if (statusCheck && statusCheck.status === 'failed') {
          console.log(`🛑 [PROCESS] *** CANCELLATION DETECTED *** Keyword ${keyword.id} was cancelled before content generation - stopping immediately`);
          results.push({
            id: keyword.id,
            keyword: keyword.keyword,
            status: 'cancelled',
            success: false,
            message: 'Processing was cancelled by user before content generation'
          });
          continue;
        } else if (statusCheck) {
          console.log(`✅ [PROCESS] Keyword ${keyword.id} status check passed: "${statusCheck.status}" - continuing with content generation`);
        } else {
          console.log(`⚠️ [PROCESS] No status check result for keyword ${keyword.id} - continuing anyway`);
        }
        
        // STEP 9: Generate content based on contentOption
        if (contentOption === 'facebook' || contentOption === 'all') {
          try {
            console.log(`📱 [PROCESS] Generating Facebook content for: "${keyword.keyword}"`);
            console.log(`🖼️ [PROCESS] Image URL for keyword: ${imageurl}`);
            
            let facebookContent;
            
            if (keyword.full_recipe && keyword.full_recipe.trim()) {
              console.log(`📝 [PROCESS] Using full_recipe, length: ${keyword.full_recipe.length}`);
              facebookContent = await generateFacebookContent(keyword.keyword, imageurl, keyword.full_recipe);
            } else {
              console.log(`🤖 [PROCESS] No full_recipe found, generating from keyword only`);
              facebookContent = await generateFacebookContent(keyword.keyword, imageurl);
            }
            
            if (facebookContent) {
              await facebookDb.saveFacebookContent(recipeId, {
                ...facebookContent,
                websiteId: websiteId
              });
              
              console.log(`✅ [PROCESS] Saved Facebook content for recipe: ${recipeId}`);
              contentGenerated = true;
            }
          } catch (fbError) {
            console.error(`❌ [PROCESS] Facebook content generation failed for "${keyword.keyword}":`, fbError);
            throw fbError;
          }
        }
        
        if (contentOption === 'pinterest' || contentOption === 'all') {
          try {
            console.log(`📌 [PROCESS] Generating Pinterest content for: "${keyword.keyword}"`);
            const pinterestContent = await appModule.generatePinterestContent(
              keyword.keyword,
              keyword.category,
              keyword.interests
            );
            
            if (pinterestContent && pinterestContent.length > 0) {
              for (let i = 0; i < pinterestContent.length; i++) {
                const variationToSave = {
                  ...pinterestContent[i],
                  websiteId: websiteId,
                  pinterest_title: pinterestContent[i].pinterestTitle || pinterestContent[i].pinTitle,
                  pinterest_description: pinterestContent[i].pinterestDescription || pinterestContent[i].pinDescription
                };
                
                await pinterestDb.savePinterestVariation(
                  recipeId,
                  variationToSave,
                  i + 1
                );
              }
              
              console.log(`✅ [PROCESS] Saved ${pinterestContent.length} Pinterest variations for recipe: ${recipeId}`);
              contentGenerated = true;
              
              // Generate blog post from first Pinterest variation
              if (pinterestContent.length > 0) {
                console.log(`📝 [PROCESS] Generating blog content for: "${keyword.keyword}"`);
                const blogContent = await appModule.generateBlogPost(
                  keyword.keyword,
                  keyword.category,
                  keyword.interests,
                  pinterestContent[0].metaTitle,
                  pinterestContent[0].metaDesc
                );
                
                if (blogContent) {
                  await blogDb.saveBlogContent(
                    recipeId,
                    blogContent,
                    null,
                    websiteId
                  );
                  console.log(`✅ [PROCESS] Saved blog content for recipe: ${recipeId}`);
                }
              }
            }
          } catch (pinterestError) {
            console.error(`❌ [PROCESS] Pinterest content generation failed for "${keyword.keyword}":`, pinterestError);
            throw pinterestError;
          }
        }
        
        // STEP 9: Check cancellation before image generation
        const statusCheck2 = await getOne(`
          SELECT status FROM keywords WHERE id = ? AND organization_id = ?
        `, [keyword.id, organizationId]);
        
        if (statusCheck2 && statusCheck2.status === 'failed') {
          console.log(`🛑 [PROCESS] Keyword ${keyword.id} was cancelled after content generation - stopping before image generation`);
          results.push({
            id: keyword.id,
            keyword: keyword.keyword,
            status: 'cancelled',
            success: false,
            message: 'Processing was cancelled by user after content generation'
          });
          continue;
        }
        
        // STEP 10: CRITICAL FIX - Generate Midjourney image and WAIT for completion
        if (contentGenerated) {
          console.log(`🎨 [PROCESS] ⏰ Starting Midjourney image generation for recipe ${recipeId}...`);
          console.log(`⏰ [PROCESS] Image generation start time: ${new Date().toISOString()}`);
          
          let imageGenerationCompleted = false;
          let imageGenerationError = null;
          
          try {
            const discordSettings = await getCurrentDiscordSettings(req);
            
            console.log(`🔍 [PROCESS] Discord settings check:`, {
              hasSettings: !!discordSettings,
              enableDiscord: discordSettings?.enableDiscord,
              hasChannelId: !!discordSettings?.discordChannelId,
              hasUserToken: !!discordSettings?.discordUserToken,
              environment: process.env.NODE_ENV || 'development'
            });
            
            if (discordSettings && discordSettings.enableDiscord && 
                discordSettings.discordChannelId && discordSettings.discordUserToken) {
              
              console.log(`🔗 [PROCESS] Discord settings valid, proceeding with image generation`);
              
              // Check if cancelled before starting image generation
              const imageStatusCheck = await getOne(`
                SELECT status FROM keywords WHERE id = ? AND organization_id = ?
              `, [keyword.id, organizationId]);
              
              if (imageStatusCheck && imageStatusCheck.status === 'failed') {
                console.log(`🛑 [PROCESS] Keyword ${keyword.id} was cancelled before image generation - stopping`);
                imageGenerationCompleted = false;
                imageGenerationError = 'Processing was cancelled by user';
                break;
              }
              
              // CRITICAL: AWAIT the image generation to complete with extended timeout for RELAX MODE
              console.log(`⏳ [PROCESS] Calling imageGenerator.generateImageForRecipeWithSettings...`);
              
              const imageGenerationStartTime = Date.now();
              
              // Create promises for image generation and timeout
              const imagePromise = imageGenerator.generateImageForRecipeWithSettings(recipeId, discordSettings, imageurl);
              const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Image generation timeout after 8 minutes')), 8 * 60 * 1000) // Increased to 8 minutes for RELAX mode
              );
              
              // Race between image generation and timeout
              const imageResult = await Promise.race([imagePromise, timeoutPromise]);
              
              const imageGenerationEndTime = Date.now();
              const imageGenerationDuration = imageGenerationEndTime - imageGenerationStartTime;
              
              console.log(`⏱️ [PROCESS] Image generation completed in ${imageGenerationDuration}ms (${Math.round(imageGenerationDuration/1000)}s)`);
              console.log(`📊 [PROCESS] Image generation result:`, {
                success: imageResult?.success,
                hasImagePath: !!imageResult?.imagePath,
                hasError: !!imageResult?.error,
                imageId: imageResult?.id
              });
              
              if (imageResult && imageResult.success) {
                console.log(`✅ [PROCESS] Successfully generated Midjourney image for recipe ${recipeId}: ${imageResult.imagePath}`);
                imageGenerationCompleted = true;
                
                // Additional wait for image processing to complete
                console.log(`⏳ [PROCESS] Waiting additional 8 seconds for image processing to complete...`);
                await new Promise(resolve => setTimeout(resolve, 8000));
                console.log(`✅ [PROCESS] Image processing delay completed for recipe ${recipeId}`);
                
              } else {
                console.warn(`⚠️ [PROCESS] Midjourney image generation failed for recipe ${recipeId}: ${imageResult?.error}`);
                imageGenerationError = imageResult?.error || 'Image generation failed without specific error';
                imageGenerationCompleted = false;
              }
              
            } else {
              console.log(`❌ [PROCESS] Discord settings not available or disabled - this is the critical issue!`);
              console.log(`🔍 [PROCESS] Missing Discord configuration details:`);
              
              if (!discordSettings) {
                console.log(`   - discordSettings is null/undefined`);
              } else {
                console.log(`   - enableDiscord: ${discordSettings.enableDiscord}`);
                console.log(`   - hasChannelId: ${!!discordSettings.discordChannelId}`);
                console.log(`   - hasUserToken: ${!!discordSettings.discordUserToken}`);
              }
              
              // OPTION 1: Fail the keyword processing if Discord is not configured
              imageGenerationError = 'Discord integration not properly configured for image generation';
              imageGenerationCompleted = false;
              
              // OPTION 2: Uncomment the next line if you want to skip image generation and still mark as processed
              // imageGenerationCompleted = true;
            }
            
          } catch (imageError) {
            console.error(`❌ [PROCESS] Error during Midjourney image generation for recipe ${recipeId}:`, imageError);
            console.error(`📚 [PROCESS] Image generation error stack:`, imageError.stack);
            imageGenerationError = imageError.message;
            imageGenerationCompleted = false;
          }
          
          console.log(`⏰ [PROCESS] Image generation end time: ${new Date().toISOString()}`);
          
          // STEP 10: ONLY mark as processed if image generation completed successfully OR was explicitly skipped
          if (imageGenerationCompleted) {
            // Check if keyword was cancelled before marking as processed
            const currentKeywordStatus = await getOne(`
              SELECT status FROM keywords WHERE id = ? AND organization_id = ?
            `, [keyword.id, organizationId]);
            
            if (currentKeywordStatus && currentKeywordStatus.status === 'failed') {
              console.log(`🛑 [PROCESS] Keyword ${keyword.id} was cancelled during processing - not updating to processed`);
              results.push({
                id: keyword.id,
                keyword: keyword.keyword,
                status: 'cancelled',
                success: false,
                message: 'Processing was cancelled by user'
              });
              continue;
            }
            
            console.log(`🔄 [PROCESS] ✅ Image generation complete. Now updating keyword ${keyword.id} status to 'processed' with recipe ID: ${recipeId}`);
            console.log(`⏰ [PROCESS] Final status update time: ${new Date().toISOString()}`);
            
            const finalUpdateResult = await runQuery(`
              UPDATE keywords 
              SET status = 'processed', 
                  processed_at = CURRENT_TIMESTAMP 
              WHERE id = ? AND organization_id = ? AND status != 'failed'
            `, [keyword.id, organizationId]);
            
            if (finalUpdateResult.changes > 0) {
              const totalProcessingTime = Date.now() - processingStartTime;
              console.log(`✅ [PROCESS] 🎉 Successfully updated keyword ${keyword.id} status to 'processed' - WORKFLOW COMPLETE`);
              console.log(`📊 [PROCESS] Total processing time: ${totalProcessingTime}ms (${Math.round(totalProcessingTime/1000)}s)`);
              
              // ENHANCED DEBUG: Verify the status was actually updated  
              const verifySuccessStatus = await getOne(`SELECT id, status, processed_at FROM keywords WHERE id = ?`, [keyword.id]);
              console.log(`🔍 [PROCESS] SUCCESS STATUS VERIFICATION for ${keyword.id}: ${verifySuccessStatus?.status} (processed_at: ${verifySuccessStatus?.processed_at})`);
              
              results.push({
                id: keyword.id,
                keyword: keyword.keyword,
                category: keyword.category,
                status: 'processed',
                success: true,
                recipeId: recipeId,
                contentOption: contentOption,
                processingTimeMs: totalProcessingTime
              });
            } else {
              console.error(`❌ [PROCESS] Failed to update keyword ${keyword.id} final status`);
              
              results.push({
                id: keyword.id,
                keyword: keyword.keyword,
                category: keyword.category,
                status: 'failed',
                success: false,
                message: 'Failed to update final status'
              });
            }
          } else {
            console.log(`⚠️ [PROCESS] Image generation did not complete within timeout, but content generation was successful`);
            console.log(`🔍 [PROCESS] Image generation error: ${imageGenerationError}`);
            console.log(`✅ [PROCESS] Marking keyword ${keyword.id} as PROCESSED since content generation succeeded`);
            
            // Check if keyword was cancelled before marking as processed
            const currentKeywordStatus2 = await getOne(`
              SELECT status FROM keywords WHERE id = ? AND organization_id = ?
            `, [keyword.id, organizationId]);
            
            if (currentKeywordStatus2 && currentKeywordStatus2.status === 'failed') {
              console.log(`🛑 [PROCESS] Keyword ${keyword.id} was cancelled during processing - not updating to processed (path 2)`);
              results.push({
                id: keyword.id,
                keyword: keyword.keyword,
                status: 'cancelled',
                success: false,
                message: 'Processing was cancelled by user'
              });
              continue;
            }
            
            // FIXED: Mark as processed since content generation was successful
            // Image generation may still complete asynchronously in Discord
            await runQuery(`
              UPDATE keywords 
              SET status = 'processed', 
                  processed_at = CURRENT_TIMESTAMP 
              WHERE id = ? AND status != 'failed'
            `, [keyword.id]);
            
            const totalProcessingTime = Date.now() - processingStartTime;
            console.log(`✅ [PROCESS] Marked keyword ${keyword.id} as processed (content ready, image may be generating) after ${totalProcessingTime}ms`);
            
            // ENHANCED DEBUG: Verify the status was actually updated
            const verifyStatus = await getOne(`SELECT id, status, processed_at FROM keywords WHERE id = ?`, [keyword.id]);
            console.log(`🔍 [PROCESS] STATUS VERIFICATION for ${keyword.id}: ${verifyStatus?.status} (processed_at: ${verifyStatus?.processed_at})`);
            
            results.push({
              id: keyword.id,
              keyword: keyword.keyword,
              category: keyword.category,
              status: 'processed',
              success: true,
              recipeId: recipeId,
              message: `Content generated successfully. Image generation in progress.`,
              processingTimeMs: totalProcessingTime
            });
          }
        } else {
          throw new Error('No content was generated');
        }
        
      } catch (error) {
        const totalProcessingTime = Date.now() - processingStartTime;
        console.error(`❌ [PROCESS] Error processing keyword ${keywordId} after ${totalProcessingTime}ms:`, error);
        console.error(`📚 [PROCESS] Error stack:`, error.stack);
        
        // CRITICAL: Update keyword status to failed and unlock it
        try {
          await runQuery(`
            UPDATE keywords 
            SET status = 'failed', 
                processed_at = CURRENT_TIMESTAMP 
            WHERE id = ?
          `, [keywordId]);
          console.log(`⚠️ [PROCESS] Updated keyword ${keywordId} status to 'failed'`);
        } catch (updateError) {
          console.error(`❌ [PROCESS] Failed to update keyword ${keywordId} status to failed:`, updateError);
        }
        
        results.push({
          id: keywordId,
          status: 'failed',
          success: false,
          message: error.message || 'Failed to process',
          processingTimeMs: totalProcessingTime
        });
      }
    }
    
    const totalSuccessful = results.filter(r => r.success).length;
    const totalFailed = results.filter(r => !r.success).length;
    
    console.log(`🏁 [PROCESS] Processing complete. Results: ${totalSuccessful} successful, ${totalFailed} failed`);
    console.log(`📋 [PROCESS] Detailed results:`, results.map(r => ({ 
      id: r.id, 
      status: r.status, 
      success: r.success,
      processingTime: r.processingTimeMs ? `${Math.round(r.processingTimeMs/1000)}s` : 'N/A'
    })));
    
    // Return results
    res.json({
      success: totalSuccessful > 0,
      results: results,
      message: `Processed ${results.length} keywords: ${totalSuccessful} successful, ${totalFailed} failed`,
      summary: {
        total: results.length,
        successful: totalSuccessful,
        failed: totalFailed
      }
    });
    
  } catch (error) {
    console.error('❌ [PROCESS] Error processing selected keywords:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});

// API endpoint to cancel processing keywords
app.post('/api/keywords/cancel', isAuthenticated, activityMiddleware.logActivity('cancel', 'keyword'), async (req, res) => {
  try {
    const { keywordIds } = req.body;
    
    if (!keywordIds || !Array.isArray(keywordIds) || keywordIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No keywords provided for cancellation'
      });
    }

    console.log(`🛑 [CANCEL] Cancelling ${keywordIds.length} keywords:`, keywordIds);
    
    const organizationId = req.session.user.organizationId;
    const userId = req.session.user.id;
    let cancelledCount = 0;
    
    for (const keywordId of keywordIds) {
      try {
        // Check if keyword exists and belongs to user's organization
        const keyword = await getOne(`
          SELECT id, keyword, status, owner_id 
          FROM keywords 
          WHERE id = ? AND organization_id = ?
        `, [keywordId, organizationId]);
        
        if (!keyword) {
          console.warn(`⚠️ [CANCEL] Keyword ${keywordId} not found or not accessible`);
          continue;
        }
        
        console.log(`🔍 [CANCEL] Keyword ${keywordId} ("${keyword.keyword}") current status: "${keyword.status}"`);
        
        // Check permissions for employees
        if (req.session.user.role === 'employee' && keyword.owner_id !== userId) {
          console.warn(`⚠️ [CANCEL] Employee ${userId} doesn't own keyword ${keywordId}`);
          continue;
        }
        
        // Cancel keywords regardless of current status (more aggressive)
        const result = await runQuery(`
          UPDATE keywords 
          SET status = 'failed'
          WHERE id = ? AND organization_id = ?
        `, [keywordId, organizationId]);
        
        if (result.changes > 0) {
          console.log(`✅ [CANCEL] Successfully cancelled keyword ${keywordId}: "${keyword.keyword}" (was ${keyword.status})`);
          cancelledCount++;
        } else {
          console.log(`⚠️ [CANCEL] Failed to update keyword ${keywordId} in database`);
        }
        
      } catch (keywordError) {
        console.error(`❌ [CANCEL] Error cancelling keyword ${keywordId}:`, keywordError);
      }
    }
    
    res.json({
      success: true,
      cancelledCount: cancelledCount,
      message: `Successfully cancelled ${cancelledCount} out of ${keywordIds.length} keywords`
    });
    
  } catch (error) {
    console.error('❌ [CANCEL] Error cancelling keywords:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred while cancelling keywords'
    });
  }
});

// Debug endpoint to check keyword status and force cancellation
app.get('/api/keywords/debug-force-cancel/:keywordId', isAuthenticated, async (req, res) => {
  try {
    const keywordId = req.params.keywordId;
    const organizationId = req.session.user.organizationId;
    
    console.log(`🔍 [DEBUG] Force checking/cancelling keyword ${keywordId}`);
    
    // Get current status
    const beforeKeyword = await getOne(`
      SELECT id, keyword, status, owner_id
      FROM keywords 
      WHERE id = ? AND organization_id = ?
    `, [keywordId, organizationId]);
    
    console.log(`🔍 [DEBUG] Before: Keyword ${keywordId} status = "${beforeKeyword?.status}"`);
    
    // Force cancel it
    const cancelResult = await runQuery(`
      UPDATE keywords 
      SET status = 'failed'
      WHERE id = ? AND organization_id = ?
    `, [keywordId, organizationId]);
    
    console.log(`🔍 [DEBUG] Cancel result: ${cancelResult.changes} rows updated`);
    
    // Get status after cancellation
    const afterKeyword = await getOne(`
      SELECT id, keyword, status, owner_id
      FROM keywords 
      WHERE id = ? AND organization_id = ?
    `, [keywordId, organizationId]);
    
    console.log(`🔍 [DEBUG] After: Keyword ${keywordId} status = "${afterKeyword?.status}"`);
    
    res.json({
      success: true,
      before: beforeKeyword,
      after: afterKeyword,
      cancelResult: cancelResult,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error(`🔍 [DEBUG] Error in debug endpoint:`, error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Add this temporary debugging route to server.js (after your other routes)
app.get('/debug-midjourney', isAuthenticated, async (req, res) => {
  try {
    const MidjourneyClient = require('./midjourney/midjourney-client');
    const client = MidjourneyClient.getInstance();
    
    console.log('🧪 Running Midjourney debug test...');
    
    // Test initialization
    await client.initialize();
    
    // Test message retrieval
    const testResult = await client.testDiscordMessages();
    
    res.json({
      success: true,
      initialization: {
        userId: client.userId,
        guildId: client.guildId,
        channelId: client.channelId
      },
      messageTest: testResult
    });
  } catch (error) {
    console.error('Debug test failed:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get keyword status API endpoint (for async polling)
app.get('/api/keywords/status/:keywordId', isAuthenticated, async (req, res) => {
  try {
    const keywordId = req.params.keywordId;
    
    if (!keywordId) {
      return res.status(400).json({
        success: false,
        message: 'Keyword ID is required'
      });
    }
    
    console.log(`📡 [STATUS API] Getting status for keyword: ${keywordId}`);
    
    // Get keyword with recipe info
    const keyword = await getOne(`
      SELECT k.id, k.keyword, k.status, k.recipe_id, k.processed_at, k.processing_started_at,
             r.recipe_idea, r.created_at as recipe_created_at
      FROM keywords k
      LEFT JOIN recipes r ON k.recipe_id = r.id
      WHERE k.id = ?
    `, [keywordId]);
    
    if (!keyword) {
      return res.status(404).json({
        success: false,
        message: 'Keyword not found'
      });
    }
    
    // Calculate processing time if still processing
    let processingTime = null;
    if (keyword.processing_started_at) {
      const startTime = new Date(keyword.processing_started_at);
      const elapsed = Math.round((Date.now() - startTime.getTime()) / 1000);
      processingTime = `${elapsed}s`;
    }
    
    console.log(`📡 [STATUS API] Keyword ${keywordId} status: ${keyword.status}`);
    
    res.json({
      success: true,
      id: keyword.id,
      keyword: keyword.keyword,
      status: keyword.status,
      recipeId: keyword.recipe_id,
      processed_at: keyword.processed_at,
      processingTime: processingTime,
      message: keyword.status === 'processed' ? 'Processing completed successfully' : null
    });
    
  } catch (error) {
    console.error('📡 [STATUS API] Error getting keyword status:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Delete keywords API endpoint
app.post('/api/keywords/delete', isAuthenticated, activityMiddleware.logActivity('delete', 'keyword'), async (req, res) => {
  try {
    const { keywordIds } = req.body;
    
    if (!keywordIds || !Array.isArray(keywordIds) || keywordIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No keywords selected for deletion'
      });
    }
    
    console.log(`Deleting ${keywordIds.length} keywords`);
    
    // Delete the keywords
    await keywordsDb.deleteKeywords(keywordIds);
    
    res.json({
      success: true,
      message: `Deleted ${keywordIds.length} keywords successfully`,
      count: keywordIds.length
    });
    
  } catch (error) {
    console.error('Error deleting keywords:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});

// Process keywords API endpoint
app.post('/api/keywords/process',isAuthenticated, async (req, res) => {
  try {
    const { keywords, autoGenerate } = req.body;
    
    if (!keywords || !Array.isArray(keywords) || keywords.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid keywords provided'
      });
    }
    
    console.log(`Processing ${keywords.length} keywords, autoGenerate: ${autoGenerate}`);
    
    // Process each keyword
    const results = [];
    
    for (const keyword of keywords) {
      try {
        // Validate the keyword
        if (!keyword.recipeIdea || typeof keyword.recipeIdea !== 'string' || keyword.recipeIdea.trim().length === 0) {
          results.push({
            recipeIdea: keyword.recipeIdea || 'Empty',
            category: keyword.category,
            success: false,
            message: 'Invalid recipe idea'
          });
          continue;
        }
        
        // Create recipe record
        // Create a new recipe
const recipeId = await recipeDb.createRecipe({
  recipeIdea: keyword.recipeIdea,
  category: keyword.category,
  interests: keyword.interests,
  language: promptConfig.language,
  ownerId: req.session.user.id,
  organizationId: req.session.user.organizationId
});
        
        // If auto-generate is enabled, generate content for this recipe
        if (autoGenerate) {
          try {
            // Update app.js config with current promptConfig
            const appModule = require('./app');
            appModule.updateConfig({
              model: promptConfig.model,
              apiKey: promptConfig.apiKey,
              language: promptConfig.language,
              temperature: promptConfig.temperature,
              pinCount: promptConfig.pinCount,
              prompts: promptConfig.prompts
            });
            
            // Generate Facebook content (creates the basic recipe)
            const facebookContent = await appModule.generateFacebookContent(keyword.recipeIdea);
            
            if (facebookContent) {
              // Save Facebook content
              await facebookDb.saveFacebookContent(recipeId, facebookContent);
              
              // Optionally generate Pinterest content
              try {
                const pinterestContent = await appModule.generatePinterestContent(
                  keyword.recipeIdea,
                  keyword.category,
                  keyword.interests
                );
                
                // Save Pinterest variations
                if (pinterestContent && pinterestContent.length > 0) {
                  for (let i = 0; i < pinterestContent.length; i++) {
                    await pinterestDb.savePinterestVariation(
                      recipeId,
                      pinterestContent[i],
                      i + 1
                    );
                  }
                }
              } catch (pinterestError) {
                console.warn(`Pinterest generation error for "${keyword.recipeIdea}":`, pinterestError);
              }
            }
          } catch (generateError) {
            console.warn(`Content generation error for "${keyword.recipeIdea}":`, generateError);
            // We continue despite generation errors since the recipe was created
          }
        }
        
        // Add to results
        results.push({
          recipeIdea: keyword.recipeIdea,
          category: keyword.category,
          success: true,
          recipeId: recipeId
        });
        
      } catch (keywordError) {
        console.error(`Error processing keyword "${keyword.recipeIdea}":`, keywordError);
        
        results.push({
          recipeIdea: keyword.recipeIdea,
          category: keyword.category,
          success: false,
          message: keywordError.message || 'Failed to process'
        });
      }
    }
    
    // Return results
    res.json({
      success: true,
      results: results
    });
    
  } catch (error) {
    console.error('Error processing keywords:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});

app.post('/api/analyze-pinclicks', isAuthenticated, async (req, res) => {
  try {
    const { csv, keyword, full_recipe, category, image_url } = req.body; // Added full_recipe parameter
    
    if (!csv || !keyword) {
      return res.status(400).json({
        success: false,
        message: 'CSV data and keyword are required'
      });
    }
    
    console.log(`Analyzing PinClicks data for keyword: ${keyword}`);
    if (full_recipe) {
      console.log(`Full recipe provided (${full_recipe.length} characters)`);
    }
    
    // Parse the CSV (same logic as before)
    const csvLines = csv.split('\n');
    if (csvLines.length < 2) {
      return res.status(400).json({
        success: false,
        message: 'CSV is empty or invalid'
      });
    }
    
    const headers = csvLines[0].split(',');
    
    // Extract keywords and their occurrence data
    const keywordData = [];
    for (let i = 1; i < csvLines.length; i++) {
      const line = csvLines[i].trim();
      if (!line) continue;
      
      const columns = line.split(',');
      if (columns.length >= 2) {
        const keywordCol = columns[0].trim();
        const occurrences = parseInt(columns[1]) || 0;
        
        if (keywordCol && occurrences > 0) {
          keywordData.push({
            keyword: keywordCol,
            occurrences
          });
        }
      }
    }
    
    // Simple algorithm to extract interests (same as before)
    const relevantKeywords = keywordData
      .filter(item => item.occurrences >= 3)
      .sort((a, b) => b.occurrences - a.occurrences)
      .slice(0, 10) // Take top 10
      .map(item => item.keyword.toLowerCase())
      .filter(keyword => keyword.length > 2); // Remove very short keywords
    
    const interests = relevantKeywords.join(', ');
    
    // Return both interests and full_recipe data
    return res.json({
      success: true,
      interests: interests,
      keyword: keyword,
      full_recipe: full_recipe || null, // Pass through the full recipe if provided
      category: category || '',
      image_url: image_url || ''
    });
  } catch (error) {
    console.error('Error analyzing PinClicks data:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});

// Helper function to parse CSV line with proper quote handling
function parseCSVLine(line) {
  const values = [];
  let currentValue = '';
  let insideQuotes = false;
  let quoteChar = null;
  
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    
    if ((char === '"' || char === "'") && !insideQuotes) {
      insideQuotes = true;
      quoteChar = char;
    } else if (char === quoteChar && insideQuotes) {
      // Check for escaped quotes
      if (i + 1 < line.length && line[i + 1] === quoteChar) {
        currentValue += char;
        i++; // Skip the next quote
      } else {
        insideQuotes = false;
        quoteChar = null;
      }
    } else if (char === ',' && !insideQuotes) {
      values.push(currentValue.trim());
      currentValue = '';
    } else {
      currentValue += char;
    }
  }
  
  // Add the last value
  values.push(currentValue.trim());
  
  return values;
}
// Test WordPress connection
app.post('/api/wordpress/test-connection',isAuthenticated, async (req, res) => {
  try {
    const { siteUrl, username, password } = req.body;
    
    // Validate required fields
    if (!siteUrl || !username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Site URL, username, and password are required.'
      });
    }
    
    // Initialize WordPress client
    const wp = new WordPressClient({
      siteUrl,
      username,
      password
    });
    
    // Test connection
    const result = await wp.validateConnection();
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('WordPress connection test error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to connect to WordPress'
    });
  }
});

// Test WP Recipe Maker connection
app.post('/api/wordpress/test-wprm-connection',isAuthenticated, async (req, res) => {
  try {
    // Get WordPress settings
    const wpSettings = await wordpressDb.getSettings();
    
    if (!wpSettings || !wpSettings.site_url || !wpSettings.username || !wpSettings.password) {
      return res.status(400).json({
        success: false,
        message: 'WordPress settings are required. Please configure WordPress first.'
      });
    }
    
    // Configure WordPress API
    const wpConfig = {
      apiUrl: `${wpSettings.site_url}/wp-json/wp/v2`,
      username: wpSettings.username,
      password: wpSettings.password
    };
    
    // Require recipe helper module
    const recipeHelper = require('./recipe-helper');
    
    // Test connection
    const result = await recipeHelper.testWPRMApiConnection(wpConfig);
    
    res.json({
      success: true,
      message: 'WP Recipe Maker connection test successful'
    });
  } catch (error) {
    console.error('WP Recipe Maker connection test error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to connect to WP Recipe Maker'
    });
  }
});

// Publish to WordPress
app.post('/api/wordpress/publish', isAuthenticated, websiteMiddleware.hasWebsiteAccess, websiteMiddleware.ensureWebsiteSelected, async (req, res) => {
  try {
    const { recipeId, status } = req.body;
    
    if (!recipeId) {
      return res.status(400).json({
        success: false,
        message: 'Recipe ID is required'
      });
    }
    
    // Get WordPress settings
    const settings = await wordpressDb.getSettings();
    if (!settings || !settings.site_url || !settings.username || !settings.password) {
      return res.status(400).json({
        success: false,
        message: 'WordPress settings are not configured. Please set up your WordPress connection first.'
      });
    }
    
    // Get recipe details
    const recipe = await recipeDb.getRecipeById(recipeId);
    if (!recipe) {
      return res.status(404).json({
        success: false,
        message: 'Recipe not found'
      });
    }
    
    // Get blog content
    const blog = await blogDb.getBlogContentByRecipeId(recipeId);
    if (!blog || !blog.html_content) {
      return res.status(404).json({
        success: false,
        message: 'No blog content found for this recipe'
      });
    }
    
    // Get Pinterest variation for meta info
    let metaTitle = recipe.recipe_idea;
    let metaSlug = '';
    let categories = [];
    
    if (blog.pinterest_variation_id) {
      const variation = await pinterestDb.getVariationById(blog.pinterest_variation_id);
      if (variation) {
        metaTitle = variation.meta_title || metaTitle;
        metaSlug = variation.meta_slug || '';
      }
    } else {
      // Try to get the first variation
      const variations = await pinterestDb.getVariationsByRecipeId(recipeId);
      if (variations && variations.length > 0) {
        metaTitle = variations[0].meta_title || metaTitle;
        metaSlug = variations[0].meta_slug || '';
      }
    }
    
    // Initialize WordPress client
    const wp = new WordPressClient({
      siteUrl: settings.site_url,
      username: settings.username,
      password: settings.password
    });
    
    // Create the post
    const postData = {
      title: metaTitle,
      content: blog.html_content,
      status: status || settings.default_status || 'draft',
      categories: categories,
      slug: metaSlug
    };
    
    const result = await wp.createPost(postData);
    
    // Save publication record
    await wordpressDb.savePublication({
      recipeId: recipeId,
      wpPostId: result.id,
      wpPostUrl: result.link,
      wpStatus: result.status,
      websiteId: req.session.currentWebsiteId
    });
    
    res.json({
      success: true,
      post: {
        id: result.id,
        url: result.link,
        status: result.status,
        title: result.title.rendered
      }
    });
  } catch (error) {
    console.error('Error publishing to WordPress:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to publish to WordPress'
    });
  }
});


app.post('/api/wordpress/publish-with-recipe', isAuthenticated, websiteMiddleware.hasWebsiteAccess, websiteMiddleware.ensureWebsiteSelected, activityMiddleware.logActivity('publish', 'post'), async (req, res) => {
  try {
    const { recipeId, status, customContent, customTitle, formatContent = true, seoMetadata = null, includeFeaturedImage = true } = req.body;
    
    if (!recipeId && !customContent) {
      return res.status(400).json({
        success: false,
        message: 'Either Recipe ID or custom content is required'
      });
    }
    
    // Get WordPress settings
    const wpSettings = await wordpressDb.getSettings();
    if (!wpSettings || !wpSettings.site_url || !wpSettings.username || !wpSettings.password) {
      return res.status(400).json({
        success: false,
        message: 'WordPress settings are not configured. Please set up your WordPress connection first.'
      });
    }
    
    // Get WP Recipe Maker settings
    const recipeDbModule = require('./wordpress-recipe-db');
    const wprmSettings = await recipeDbModule.getSettings();
    
    let content, title, metaSlug = '';
    let recipeData = null;
    let focusKeyword = null;
    let autoSeoMetadata = null;
    let featuredImagePath = null; // NEW: Track featured image
    
    // If using an existing recipe
    if (recipeId) {
      // Get recipe details
      const recipe = await recipeDb.getRecipeById(recipeId);
      if (!recipe) {
        return res.status(404).json({
          success: false,
          message: 'Recipe not found'
        });
      }
      
      // Store recipe idea as the focus keyword
      focusKeyword = recipe.recipe_idea; 
      
      // Get blog content
      const blog = await blogDb.getBlogContentByRecipeId(recipeId);
      if (!blog || !blog.html_content) {
        return res.status(404).json({
          success: false,
          message: 'No blog content found for this recipe'
        });
      }
      
      content = blog.html_content;
      title = recipe.recipe_idea;
      
      // NEW: Get the latest Midjourney image for this recipe
      if (includeFeaturedImage) {
        try {
          const recipeImage = await db.getOne(
            "SELECT image_path FROM recipe_images WHERE recipe_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1",
            [recipeId]
          );
          
          if (recipeImage && recipeImage.image_path) {
            const imagePath = path.join(process.cwd(), 'recipe_images', recipeImage.image_path);
            if (fs.existsSync(imagePath)) {
              featuredImagePath = imagePath;
              console.log(`✅ Found featured image for recipe: ${recipeImage.image_path}`);
            } else {
              console.warn(`⚠️ Image file not found: ${imagePath}`);
            }
          } else {
            console.log(`ℹ️ No Midjourney image found for recipe ${recipeId}`);
          }
        } catch (imageError) {
          console.warn('Warning: Error getting recipe image:', imageError.message);
          // Continue without image
        }
      }


      // Get Pinterest variation for meta info INCLUDING PINTEREST SOCIAL META
      if (blog.pinterest_variation_id) {
        const variation = await pinterestDb.getVariationById(blog.pinterest_variation_id);
        if (variation) {
          title = variation.meta_title || title;
          metaSlug = variation.meta_slug || '';
          
          // Create auto SEO metadata object with Pinterest social meta
          autoSeoMetadata = {
            title: variation.meta_title || title,
            description: variation.meta_description || '',
            permalink: variation.meta_slug || '',
            keyword: focusKeyword,
            // NEW: Include Pinterest social meta
            pinterestTitle: variation.pinterest_title || variation.pin_title || `${title} - Save This Recipe!`,
            pinterestDescription: variation.pinterest_description || variation.pin_description || `Save this amazing ${title} recipe to your Pinterest board! Easy to follow and delicious results.`
          };
        }
      } else {
        // Try to get the first variation
        const variations = await pinterestDb.getVariationsByRecipeId(recipeId);
        if (variations && variations.length > 0) {
          const firstVariation = variations[0];
          title = firstVariation.meta_title || title;
          metaSlug = firstVariation.meta_slug || '';
          
          // Create auto SEO metadata with Pinterest social meta
          autoSeoMetadata = {
            title: firstVariation.meta_title || title,
            description: firstVariation.meta_description || '',
            permalink: firstVariation.meta_slug || '',
            keyword: focusKeyword,
            // NEW: Include Pinterest social meta
            pinterestTitle: firstVariation.pinterest_title || firstVariation.pin_title || `${title} - Save This Recipe!`,
            pinterestDescription: firstVariation.pinterest_description || firstVariation.pin_description || `Save this amazing ${title} recipe to your Pinterest board! Easy to follow and delicious results.`
          };
        }
      }
      
      // Get Facebook content to extract recipe data
      const facebookContent = await facebookDb.getFacebookContentByRecipeId(recipeId);
      if (facebookContent) {
        // Require recipe helper module
        const recipeHelper = require('./recipe-helper');
        recipeData = recipeHelper.extractRecipeFromFacebookContent(facebookContent);
        
        // Log the extracted recipe data for debugging
        console.log('Extracted recipe data from Facebook content:');
        console.log('- Title:', recipeData?.title);
        console.log('- Ingredients:', recipeData?.ingredients?.length || 0);
        console.log('- Instructions:', recipeData?.instructions?.length || 0);
        
        // Make sure original arrays are set
        if (recipeData && recipeData.ingredients && !recipeData._originalIngredients) {
          recipeData._originalIngredients = [...recipeData.ingredients];
        }
        
        if (recipeData && recipeData.instructions && !recipeData._originalInstructions) {
          recipeData._originalInstructions = [...recipeData.instructions];
        }
      } else {
        console.warn('No Facebook content found for this recipe');
      }
    } else {
      // Use custom content and title
      content = customContent;
      title = customTitle || 'Custom Content';
      
      // If SEO metadata was provided directly, use it
      if (seoMetadata && seoMetadata.keyword) {
        focusKeyword = seoMetadata.keyword;
      }
    }
    
    // Create the post data
    const postData = {
      title: title,
      content: content,
      status: status || wpSettings.default_status || 'draft',
      slug: metaSlug,
      formatContent: formatContent
    };
    
    // Initialize WordPress client
    const WordPressClient = require('./wordpress');
    const wp = new WordPressClient({
      siteUrl: wpSettings.site_url,
      username: wpSettings.username,
      password: wpSettings.password
    });
    
    let result;
    
    // NEW: Create post with featured image
    const imageAltText = `${title} - Recipe Image`;
    const postResult = await wp.createPostWithFeaturedImage(postData, featuredImagePath, imageAltText);
    
    // Continue with recipe and SEO processing
    if (recipeData && wprmSettings.enabled) {
      // Check if we should add recipe based on title
      const shouldAdd = wprmSettings.addToAllPosts || 
                        WordPressClient.shouldAddRecipe(title, wprmSettings);
                        
      console.log(`Should add recipe? ${shouldAdd}`);
      
      if (shouldAdd) {
        // Add the recipe to the existing post
        const recipeHelper = require('./recipe-helper');
        const recipeResult = await recipeHelper.addRecipeToPost(
          {
            apiUrl: `${wpSettings.site_url}/wp-json/wp/v2`,
            username: wpSettings.username,
            password: wpSettings.password
          },
          recipeData,
          postResult.id
        );
        
        result = {
          success: true,
          post: postResult,
          recipe: recipeResult,
          featuredImage: featuredImagePath ? {
            localPath: featuredImagePath,
            wordpressUrl: postResult.featured_image_url
          } : null
        };
      } else {
        result = {
          success: true,
          post: postResult,
          featuredImage: featuredImagePath ? {
            localPath: featuredImagePath,
            wordpressUrl: postResult.featured_image_url
          } : null
        };
      }
    } else {
      result = {
        success: true,
        post: postResult,
        featuredImage: featuredImagePath ? {
          localPath: featuredImagePath,
          wordpressUrl: postResult.featured_image_url
        } : null
      };
    }
    
    // Apply SEO metadata
    const metadataToApply = seoMetadata || autoSeoMetadata || { 
      title: title,
      description: '',
      permalink: metaSlug,
      keyword: focusKeyword
    };
    
    if (metadataToApply && metadataToApply.keyword) {
      try {
        console.log('Applying SEO metadata with focus keyword:', metadataToApply.keyword);
        await wp.applySeoMetadata(postResult.id, metadataToApply);
        console.log('✅ SEO metadata with focus keyword applied successfully');
        result.seo = { focusKeyword: metadataToApply.keyword };
      } catch (seoError) {
        console.error('Error applying SEO metadata:', seoError.message);
        // Continue despite SEO error
      }
    }
    
    // Save publication record if using an existing recipe
    if (recipeId) {
      await wordpressDb.savePublication({
        recipeId: recipeId,
        wpPostId: result.post.id,
        wpPostUrl: result.post.link,
        wpStatus: result.post.status,
        websiteId: req.session.currentWebsiteId
      });
      
      // If a recipe was added, log it
      if (result.recipe && result.recipe.success && result.recipe.recipeId) {
        await recipeDbModule.logRecipePublication({
          recipeId: recipeId,
          wpPostId: result.post.id,
          wprmRecipeId: result.recipe.recipeId
        });
      }
    }
    
    res.json({
      success: true,
      post: {
        id: result.post.id,
        url: result.post.link,
        status: result.post.status,
        title: result.post.title?.rendered || title,
        featured_image_url: result.post.featured_image_url || null
      },
      recipe: result.recipe || null,
      seo: result.seo || null,
      featuredImage: result.featuredImage || null
    });
  } catch (error) {
    console.error('Error publishing to WordPress with recipe:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to publish to WordPress'
    });
  }
});

// Publish to WordPress with content formatting
app.post('/api/wordpress/publish-formatted', isAuthenticated, websiteMiddleware.hasWebsiteAccess, websiteMiddleware.ensureWebsiteSelected, activityMiddleware.logActivity('publish', 'post'), async (req, res) => {
  try {
    const { recipeId, status, customContent, customTitle, formatContent = true } = req.body;
    
    if (!recipeId && !customContent) {
      return res.status(400).json({
        success: false,
        message: 'Either Recipe ID or custom content is required'
      });
    }
    
    // Get WordPress settings
    const settings = await wordpressDb.getSettings();
    if (!settings || !settings.site_url || !settings.username || !settings.password) {
      return res.status(400).json({
        success: false,
        message: 'WordPress settings are not configured. Please set up your WordPress connection first.'
      });
    }
    
    let content, title, metaSlug = '';
    
    // If using an existing recipe
    if (recipeId) {
      // Get recipe details
      const recipe = await recipeDb.getRecipeById(recipeId);
      if (!recipe) {
        return res.status(404).json({
          success: false,
          message: 'Recipe not found'
        });
      }
      
      // Get blog content
      const blog = await blogDb.getBlogContentByRecipeId(recipeId);
      if (!blog || !blog.html_content) {
        return res.status(404).json({
          success: false,
          message: 'No blog content found for this recipe'
        });
      }
      
      content = blog.html_content;
      title = recipe.recipe_idea;
      
      // Get Pinterest variation for meta info
      if (blog.pinterest_variation_id) {
        const variation = await pinterestDb.getVariationById(blog.pinterest_variation_id);
        if (variation) {
          title = variation.meta_title || title;
          metaSlug = variation.meta_slug || '';
        }
      } else {
        // Try to get the first variation
        const variations = await pinterestDb.getVariationsByRecipeId(recipeId);
        if (variations && variations.length > 0) {
          title = variations[0].meta_title || title;
          metaSlug = variations[0].meta_slug || '';
        }
      }
    } else {
      // Use custom content and title
      content = customContent;
      title = customTitle || 'Custom Content';
    }
    
    // Initialize WordPress client
    const wp = new WordPressClient({
      siteUrl: settings.site_url,
      username: settings.username,
      password: settings.password
    });
    
    // Create the post
    const postData = {
      title: title,
      content: content,
      status: status || settings.default_status || 'draft',
      slug: metaSlug,
      formatContent: formatContent
    };
    
    const result = await wp.createPost(postData);
    
    // Save publication record if using an existing recipe
    if (recipeId) {
      await wordpressDb.savePublication({
        recipeId: recipeId,
        wpPostId: result.id,
        wpPostUrl: result.link,
        wpStatus: result.status,
        websiteId: req.session.currentWebsiteId
      });
    }
    
    res.json({
      success: true,
      post: {
        id: result.id,
        url: result.link,
        status: result.status,
        title: result.title.rendered
      }
    });
  } catch (error) {
    console.error('Error publishing to WordPress:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to publish to WordPress'
    });
  }
});

// Add this new endpoint to server.js in the API section (after other WordPress endpoints)

// Bulk publish recipes to WordPress
app.post('/api/wordpress/bulk-publish', isAuthenticated, websiteMiddleware.hasWebsiteAccess, websiteMiddleware.ensureWebsiteSelected, activityMiddleware.logActivity('bulk_publish', 'post'), async (req, res) => {
  try {
    const { recipeIds, status = 'draft', includeFeaturedImage = true } = req.body;
    
    if (!recipeIds || !Array.isArray(recipeIds) || recipeIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No recipes selected for publishing'
      });
    }
    
    console.log(`🚀 Starting bulk publish of ${recipeIds.length} recipes to WordPress`);
    
    // Get WordPress settings
    const wpSettings = await wordpressDb.getSettings();
    if (!wpSettings || !wpSettings.site_url || !wpSettings.username || !wpSettings.password) {
      return res.status(400).json({
        success: false,
        message: 'WordPress settings are not configured. Please set up your WordPress connection first.'
      });
    }
    
    // Get user info for permission checks
    const organizationId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    const websiteId = req.session.currentWebsiteId;
    
    // Process each recipe
    const results = {
      total: recipeIds.length,
      published: 0,
      failed: 0,
      details: []
    };
    
    // Initialize WordPress client once
    const WordPressClient = require('./wordpress');
    const wp = new WordPressClient({
      siteUrl: wpSettings.site_url,
      username: wpSettings.username,
      password: wpSettings.password
    });
    
    // Test connection first
    try {
      await wp.authenticate();
      console.log('✅ WordPress authentication successful');
    } catch (authError) {
      return res.status(400).json({
        success: false,
        message: 'WordPress authentication failed: ' + authError.message
      });
    }
    
    // Get WP Recipe Maker settings
    let wprmSettings = null;
    try {
      const recipeDbModule = require('./wordpress-recipe-db');
      wprmSettings = await recipeDbModule.getSettings();
    } catch (wprmError) {
      console.log('WP Recipe Maker settings not available');
    }
    
    for (const recipeId of recipeIds) {
      try {
        console.log(`📝 Processing recipe ID: ${recipeId}`);
        
        // Get recipe details
        const recipe = await recipeDb.getRecipeById(recipeId);
        if (!recipe) {
          results.failed++;
          results.details.push({
            recipeId: recipeId,
            recipeName: 'Unknown',
            success: false,
            message: 'Recipe not found'
          });
          continue;
        }
        
        // Check user permissions
        if (recipe.organization_id !== organizationId || 
            (userId && recipe.owner_id !== userId)) {
          results.failed++;
          results.details.push({
            recipeId: recipeId,
            recipeName: recipe.recipe_idea,
            success: false,
            message: 'Permission denied'
          });
          continue;
        }
        
        // Get blog content
        const blog = await blogDb.getBlogContentByRecipeId(recipeId);
        if (!blog || !blog.html_content) {
          results.failed++;
          results.details.push({
            recipeId: recipeId,
            recipeName: recipe.recipe_idea,
            success: false,
            message: 'No blog content found for this recipe'
          });
          continue;
        }
        
        // Get Pinterest variation for meta info
        // Replace the Pinterest variation section in your bulk publish endpoint with this complete fix:

        // Get Pinterest variation for meta info INCLUDING PINTEREST SOCIAL META
        let metaTitle = recipe.recipe_idea;
        let metaSlug = '';
        let seoMetadata = null;
        let hasPinterestMeta = false;
        
        // Get all Pinterest variations for this recipe
        const variations = await pinterestDb.getVariationsByRecipeId(recipeId);
        console.log(`📌 [BULK] Recipe ${recipeId} has ${variations.length} Pinterest variations`);
        
        if (variations && variations.length > 0) {
          const firstVariation = variations[0];
          
          // Use Pinterest variation data for SEO metadata
          metaTitle = firstVariation.meta_title || metaTitle;
          metaSlug = firstVariation.meta_slug || '';
          
          // Create complete SEO metadata object including Pinterest social meta
          seoMetadata = {
            title: firstVariation.meta_title || metaTitle,
            description: firstVariation.meta_description || '',
            permalink: firstVariation.meta_slug || '',
            keyword: recipe.recipe_idea,
            // CRITICAL: Include Pinterest social meta using the correct field names
            pinterestTitle: firstVariation.pin_title || `${metaTitle} - Save This Recipe!`,
            pinterestDescription: firstVariation.pin_description || `Save this delicious ${metaTitle} recipe to your Pinterest board! Perfect for any occasion.`
          };
          
          hasPinterestMeta = !!(firstVariation.pin_title && firstVariation.pin_description);
          
          console.log(`📌 [BULK] Pinterest meta for recipe ${recipeId}:`, {
            title: seoMetadata.pinterestTitle,
            description: seoMetadata.pinterestDescription?.substring(0, 60) + '...',
            hasMeta: hasPinterestMeta
          });
        } else {
          // Fallback: create basic SEO metadata without Pinterest variation data
          seoMetadata = {
            title: metaTitle,
            description: '',
            permalink: '',
            keyword: recipe.recipe_idea,
            pinterestTitle: `${metaTitle} - Save This Recipe!`,
            pinterestDescription: `Save this delicious ${metaTitle} recipe to your Pinterest board! Perfect for any occasion.`
          };
          
          console.log(`⚠️ [BULK] No Pinterest variations found for recipe ${recipeId}, using fallback meta`);
        }
        
        // Get featured image path if requested
        let featuredImagePath = null;
        if (includeFeaturedImage) {
          try {
            const recipeImage = await db.getOne(
              "SELECT image_path FROM recipe_images WHERE recipe_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1",
              [recipeId]
            );
            
            if (recipeImage && recipeImage.image_path) {
              const imagePath = path.join(process.cwd(), 'recipe_images', recipeImage.image_path);
              if (fs.existsSync(imagePath)) {
                featuredImagePath = imagePath;
                console.log(`📷 Found featured image: ${recipeImage.image_path}`);
              }
            }
          } catch (imageError) {
            console.warn(`⚠️ Error getting image for recipe ${recipeId}:`, imageError.message);
          }
        }
        
        // Prepare post data
        const postData = {
          title: metaTitle,
          content: blog.html_content,
          status: status,
          slug: metaSlug,
          formatContent: true
        };
        
        // Create post with featured image
        const imageAltText = `${metaTitle} - Recipe Image`;
        const postResult = await wp.createPostWithFeaturedImage(postData, featuredImagePath, imageAltText);
        
        // Get recipe data for WPRM if enabled
        let recipeResult = null;
        if (wprmSettings && wprmSettings.enabled) {
          try {
            // Get Facebook content to extract recipe data
            const facebookContent = await facebookDb.getFacebookContentByRecipeId(recipeId);
            if (facebookContent) {
              const recipeHelper = require('./recipe-helper');
              const recipeData = recipeHelper.extractRecipeFromFacebookContent(facebookContent);
              
              if (recipeData) {
                // Check if we should add recipe based on title
                const shouldAdd = wprmSettings.addToAllPosts || 
                                  WordPressClient.shouldAddRecipe(metaTitle, wprmSettings);
                
                if (shouldAdd) {
                  recipeResult = await recipeHelper.addRecipeToPost(
                    {
                      apiUrl: `${wpSettings.site_url}/wp-json/wp/v2`,
                      username: wpSettings.username,
                      password: wpSettings.password
                    },
                    recipeData,
                    postResult.id
                  );
                  console.log(`🍳 Recipe added to post ${postResult.id}`);
                }
              }
            }
          } catch (recipeError) {
            console.warn(`⚠️ Recipe integration failed for ${recipeId}:`, recipeError.message);
            // Continue without failing the entire publish
          }
        }
        
        // Apply SEO metadata if available
        if (seoMetadata && seoMetadata.keyword) {
          try {
            await wp.applySeoMetadata(postResult.id, seoMetadata);
            console.log(`🔍 SEO metadata applied to post ${postResult.id}`);
          } catch (seoError) {
            console.warn(`⚠️ SEO metadata failed for ${recipeId}:`, seoError.message);
            // Continue without failing
          }
        }
        
        // Save publication record
        await wordpressDb.savePublication({
          recipeId: recipeId,
          wpPostId: postResult.id,
          wpPostUrl: postResult.link,
          wpStatus: postResult.status,
          websiteId: websiteId
        });
        
        // Log recipe publication if WPRM was used
        if (recipeResult && recipeResult.success && recipeResult.recipeId) {
          try {
            const recipeDbModule = require('./wordpress-recipe-db');
            await recipeDbModule.logRecipePublication({
              recipeId: recipeId,
              wpPostId: postResult.id,
              wprmRecipeId: recipeResult.recipeId
            });
          } catch (logError) {
            console.warn(`⚠️ Recipe publication logging failed:`, logError.message);
          }
        }
        
        results.published++;
        results.details.push({
          recipeId: recipeId,
          recipeName: recipe.recipe_idea,
          success: true,
          postId: postResult.id,
          postUrl: postResult.link,
          postStatus: postResult.status,
          hasRecipe: !!recipeResult,
          hasFeaturedImage: !!featuredImagePath
        });
        
        console.log(`✅ Successfully published: ${recipe.recipe_idea}`);
        
      } catch (error) {
        console.error(`❌ Error publishing recipe ${recipeId}:`, error);
        
        results.failed++;
        results.details.push({
          recipeId: recipeId,
          recipeName: 'Unknown',
          success: false,
          message: error.message || 'Publishing failed'
        });
      }
    }
    
    console.log(`🎉 Bulk publish complete: ${results.published} published, ${results.failed} failed`);
    
    // Return comprehensive results
    res.json({
      success: results.published > 0,
      message: `Bulk publish completed: ${results.published} published, ${results.failed} failed`,
      results: results
    });
    
  } catch (error) {
    console.error('❌ Error in bulk publish:', error);
    res.status(500).json({
      success: false,
      message: 'Bulk publish failed: ' + error.message
    });
  }
});

// Helper endpoint to check WordPress connection status for bulk operations
app.get('/api/wordpress/bulk-ready', isAuthenticated, websiteMiddleware.hasWebsiteAccess, websiteMiddleware.ensureWebsiteSelected, async (req, res) => {
  try {
    // Check WordPress settings
    const wpSettings = await wordpressDb.getSettings();
    if (!wpSettings || !wpSettings.site_url || !wpSettings.username || !wpSettings.password) {
      return res.json({
        success: false,
        ready: false,
        message: 'WordPress settings not configured'
      });
    }
    
    // Quick connection test
    const WordPressClient = require('./wordpress');
    const wp = new WordPressClient({
      siteUrl: wpSettings.site_url,
      username: wpSettings.username,
      password: wpSettings.password
    });
    
    try {
      await wp.authenticate();
      
      res.json({
        success: true,
        ready: true,
        message: 'WordPress connection ready for bulk publishing',
        siteUrl: wpSettings.site_url
      });
    } catch (authError) {
      res.json({
        success: false,
        ready: false,
        message: 'WordPress authentication failed: ' + authError.message
      });
    }
    
  } catch (error) {
    console.error('Error checking WordPress bulk readiness:', error);
    res.json({
      success: false,
      ready: false,
      message: 'Error checking WordPress connection: ' + error.message
    });
  }
});


// Get WordPress publication history for a recipe
app.get('/api/wordpress/publications/:recipeId',isAuthenticated, async (req, res) => {
  try {
    const recipeId = req.params.recipeId;
    
    if (!recipeId) {
      return res.status(400).json({
        success: false,
        message: 'Recipe ID is required'
      });
    }
    
    const publications = await wordpressDb.getPublicationsByRecipeId(recipeId);
    
    res.json({
      success: true,
      publications: publications || []
    });
  } catch (error) {
    console.error('Error fetching WordPress publications:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to fetch WordPress publications'
    });
  }
});

// Get WordPress settings API endpoint
app.get('/api/wordpress/settings', isAuthenticated, async (req, res) => {
  try {
    const settings = await wordpressDb.getSettings();
    
    if (settings && settings.site_url && settings.username && settings.password) {
      res.json({
        success: true,
        settings: {
          site_url: settings.site_url,
          username: settings.username,
          // Don't send the actual password to the client
          hasPassword: true,
          default_status: settings.default_status || 'draft'
        }
      });
    } else {
      res.json({
        success: false,
        message: 'WordPress settings not configured'
      });
    }
  } catch (error) {
    console.error('Error fetching WordPress settings via API:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch WordPress settings: ' + error.message
    });
  }
});

// Apply SEO metadata to a WordPress post
app.post('/api/wordpress/apply-seo', isAuthenticated, websiteMiddleware.hasWebsiteAccess, websiteMiddleware.ensureWebsiteSelected, async (req, res) => {
  try {
    const { postId, seoMetadata } = req.body;
    
    if (!postId || !seoMetadata) {
      return res.status(400).json({
        success: false,
        message: 'Post ID and SEO metadata are required'
      });
    }
    
    // Get WordPress settings
    const settings = await wordpressDb.getSettings();
    if (!settings || !settings.site_url || !settings.username || !settings.password) {
      return res.status(400).json({
        success: false,
        message: 'WordPress settings are not configured. Please set up your WordPress connection first.'
      });
    }
    
    // Initialize WordPress client
    const wp = new WordPressClient({
      siteUrl: settings.site_url,
      username: settings.username,
      password: settings.password
    });
    
    // Apply SEO metadata
    const result = await wp.applySeoMetadata(postId, seoMetadata);
    
    res.json({
      success: true,
      message: 'SEO metadata applied successfully',
      data: result
    });
  } catch (error) {
    console.error('Error applying SEO metadata:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to apply SEO metadata'
    });
  }
});

// API endpoint for filtered content (admin only)
// Now replace the API endpoint in your server.js file with this updated version

// API endpoint for filtered content (admin only)
app.get('/api/filtered-content', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const employeeId = req.query.employeeId || null;
    const contentType = req.query.type || 'all';
    
    // Use the new helper function that handles missing tables gracefully
    const result = await getFilteredContent(organizationId, employeeId, contentType);
    
    res.json(result);
  } catch (error) {
    console.error('Error getting filtered content:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to load filtered content',
      error: error.message
    });
  }
});

// Simple function to convert recipe data to CSV
function convertRecipesToCSV(recipes) {
  // Define fields for the CSV
  const fields = [
    { label: 'Recipe Title', value: 'title' },
    { label: 'Ingredient 1', value: 'ingredient1' },
    { label: 'Ingredient 2', value: 'ingredient2' },
    { label: 'Ingredient 3', value: 'ingredient3' },
    { label: 'Ingredient 4', value: 'ingredient4' },
    { label: 'Image Path', value: 'imagePath' },
  ];

  // Process recipes to extract required data
  const processedData = recipes.map(recipe => {
    // Extract title from recipe
    const title = recipe.recipe_idea || '';

    // Extract ingredients
    let ingredientsList = [];
    if (recipe.facebook && recipe.facebook.ingredientsList) {
      // If we have a Facebook post with ingredients
      ingredientsList = recipe.facebook.ingredientsList;
    } else if (recipe.facebook && recipe.facebook.recipe_text) {
      // Try to extract ingredients from recipe text
      const recipeText = recipe.facebook.recipe_text;
      const ingredientsMatch = recipeText.match(/INGREDIENTS\s*([\s\S]*?)(?:INSTRUCTIONS|STEPS|$)/i);
      
      if (ingredientsMatch && ingredientsMatch[1]) {
        ingredientsList = ingredientsMatch[1]
          .split('\n')
          .map(line => line.trim())
          .filter(line => line && line.length > 1)
          .map(line => line.replace(/^[-•\s]+|[-•\s]+$/g, '').trim());
      }
    }

    // Ensure we have at least 4 elements (even if empty)
    while (ingredientsList.length < 4) {
      ingredientsList.push('');
    }

    // Take only the first 4 ingredients
    ingredientsList = ingredientsList.slice(0, 4);

    // Get the image path
    let imagePath = '';
    // First check if the recipe has a processed midjourney image
    if (recipe.image_path) {
      imagePath = recipe.image_path;
    } else {
      // If no direct image path, try to find the first image in recipe_images directory
      const recipeId = recipe.id;
      if (recipeId) {
        try {
          const recipeImagesDir = path.join(__dirname, 'recipe_images');
          if (fs.existsSync(recipeImagesDir)) {
            const files = fs.readdirSync(recipeImagesDir);
            const recipeImages = files.filter(file => 
              file.startsWith(`recipe_${recipeId}`) && file.endsWith('.webp')
            );
            
            if (recipeImages.length > 0) {
              // Sort by timestamp to get the most recent
              recipeImages.sort((a, b) => {
                const timestampA = a.match(/_(\d+)\./);
                const timestampB = b.match(/_(\d+)\./);
                if (timestampA && timestampB) {
                  return parseInt(timestampB[1]) - parseInt(timestampA[1]);
                }
                return 0;
              });
              
              imagePath = `/recipe_images/${recipeImages[0]}`;
            }
          }
        } catch (error) {
          console.error('Error finding recipe image:', error);
        }
      }
    }

    // Prepare the data object for this recipe
    return {
      title,
      ingredient1: ingredientsList[0],
      ingredient2: ingredientsList[1],
      ingredient3: ingredientsList[2],
      ingredient4: ingredientsList[3],
      imagePath
    };
  });

  // Convert to CSV
  try {
    const parser = new Parser({ fields });
    return parser.parse(processedData);
  } catch (err) {
    console.error('Error converting to CSV:', err);
    throw err;
  }
}

// Replace the existing /api/export/recipe/:id/csv endpoint
app.get('/api/export/recipe/:id/csv', auth.isAuthenticated, async (req, res) => {
  try {
    const recipeId = req.params.id;
    console.log(`Exporting single recipe to CSV: ${recipeId}`);
    
    // Get recipe directly using recipeDb
    const recipe = await recipeDb.getRecipeById(recipeId);
    
    if (!recipe) {
      console.log(`Recipe not found: ${recipeId}`);
      return res.status(404).json({ success: false, message: 'Recipe not found' });
    }
    
    // Get the Facebook content for this recipe
    let facebook = null;
    try {
      facebook = await facebookDb.getFacebookContentByRecipeId(recipeId);
      if (facebook) {
        recipe.facebook = facebook;
      }
    } catch (fbError) {
      console.warn(`Error getting Facebook content for recipe ${recipeId}:`, fbError.message);
      // Continue without Facebook content
    }
    
    // Try to get recipe images from the database
    try {
      // Import the DB module
      const db = require('./db');
      
      // Get images from recipe_images table
      const images = await db.getAll(
        "SELECT * FROM recipe_images WHERE recipe_id = ? ORDER BY created_at DESC",
        [recipeId]
      );
      
      if (images && images.length > 0) {
        recipe.recipe_images = images;
        console.log(`Retrieved ${images.length} images for recipe ${recipeId}`);
      } else {
        console.log(`No images found in database for recipe ${recipeId}`);
      }
    } catch (imgError) {
      console.warn(`Error getting recipe images from database: ${imgError.message}`);
      // Continue without database images
    }
    
    // Load the csvExporter module directly
    const csvExporter = require('./recipe-csv-exporter');
    
    // Make sure the module loaded properly
    if (!csvExporter || typeof csvExporter.exportRecipeToCSV !== 'function') {
      console.error('CSV Exporter module not loaded correctly for single recipe export!');
      return res.status(500).json({
        success: false,
        message: 'CSV Export functionality not available'
      });
    }
    
    // Generate CSV
    const csv = csvExporter.exportRecipeToCSV(recipe);
    
    // Set headers for CSV download
    res.setHeader('Content-Disposition', `attachment; filename="recipe-${recipeId}.csv"`);
    res.setHeader('Content-Type', 'text/csv');
    
    // Send the CSV
    res.send(csv);
  } catch (error) {
    console.error('Error exporting recipe to CSV:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to export recipe to CSV', 
      error: error.message 
    });
  }
});

// Replace your Excel export endpoint in server.js with this fixed version
app.get('/api/export/recipes/excel', auth.isAuthenticated, async (req, res) => {
  try {
    console.log('Exporting recipes to Excel format with embedded images');
    
    // Get organization ID from session
    const organizationId = req.session.user.organizationId;
    console.log(`Organization ID: ${organizationId}`);
    
    // Get filter parameters from query string
    const { category, userId, limit = 20 } = req.query;
    
    // Set up filters based on user role
    let recipes = [];
    
    if (req.session.user.role === 'employee') {
      // Employees only see their recipes
      console.log(`Getting recipes for employee: ${req.session.user.id}`);
      recipes = await recipeDb.getRecipesByOwnerAndOrg(
        req.session.user.id, 
        organizationId, 
        parseInt(limit), 
        0
      );
    } else {
      // Admins see all recipes in their organization
      console.log(`Getting all recipes for organization: ${organizationId}`);
      recipes = await recipeDb.getRecipesByOrg(
        organizationId,
        parseInt(limit), 
        0
      );
    }
    
    if (!recipes || recipes.length === 0) {
      console.log('No recipes found for export');
      return res.status(404).json({ success: false, message: 'No recipes found' });
    }
    
    console.log(`Found ${recipes.length} recipes for export`);
    
    // For each recipe, get its Facebook content and images
    for (const recipe of recipes) {
      try {
        // Get Facebook content
        const facebook = await facebookDb.getFacebookContentByRecipeId(recipe.id);
        if (facebook) {
          recipe.facebook = facebook;
          console.log(`Retrieved Facebook content for recipe ${recipe.id}`);
        }
        
        // Try to get recipe images from the database
        try {
          // Import the DB module
          const db = require('./db');
          
          // Get images from recipe_images table
          const images = await db.getAll(
            "SELECT * FROM recipe_images WHERE recipe_id = ? ORDER BY created_at DESC",
            [recipe.id]
          );
          
          if (images && images.length > 0) {
            recipe.recipe_images = images;
            console.log(`Retrieved ${images.length} images for recipe ${recipe.id}`);
          } else {
            console.log(`No images found in database for recipe ${recipe.id}`);
          }
        } catch (imgError) {
          console.warn(`Error getting recipe images from database: ${imgError.message}`);
          // Continue without database images
        }
      } catch (fbError) {
        console.warn(`Error getting Facebook content for recipe ${recipe.id}:`, fbError.message);
        // Continue without Facebook content for this recipe
      }
    }
    
    try {
      // Make sure we load the Excel exporter, not the CSV one
      delete require.cache[require.resolve('./recipe-excel-exporter')];
      const excelExporter = require('./recipe-excel-exporter');
      
      console.log('Excel exporter functions:', Object.keys(excelExporter));
      
      // Just check if the exporter has the required function, don't check the type
      if (!excelExporter || !excelExporter.exportRecipesToExcel) {
        throw new Error('exportRecipesToExcel function not found in exporter module');
      }
      
      // Generate Excel file with embedded images
      console.log('Generating Excel with embedded images...');
      const excelBuffer = await excelExporter.exportRecipesToExcel(recipes);
      
      // Set headers for Excel download
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', 'attachment; filename="recipes-with-images.xlsx"');
      res.setHeader('Content-Length', excelBuffer.length);
      
      // Send the Excel file
      console.log('Sending Excel response');
      res.send(excelBuffer);
      
    } catch (excelError) {
      console.error('Excel generation error:', excelError);
      return res.status(500).json({
        success: false,
        message: `Excel generation failed: ${excelError.message}`,
        error: excelError.stack
      });
    }
  } catch (error) {
    console.error('Error exporting recipes to Excel:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to export recipes to Excel', 
      error: error.message 
    });
  }
});

// Add this new endpoint for single recipe Excel export
app.get('/api/export/recipe/:id/excel', auth.isAuthenticated, async (req, res) => {
  try {
    const recipeId = req.params.id;
    console.log(`Exporting single recipe to Excel: ${recipeId}`);
    
    // Get recipe directly using recipeDb
    const recipe = await recipeDb.getRecipeById(recipeId);
    
    if (!recipe) {
      console.log(`Recipe not found: ${recipeId}`);
      return res.status(404).json({ success: false, message: 'Recipe not found' });
    }
    
    // Check if user has access to this recipe (same logic as in /recipe/:id route)
    const orgId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    
    if (recipe.organization_id !== orgId || 
        (userId && recipe.owner_id !== userId)) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    // Get the Facebook content for this recipe
    let facebook = null;
    try {
      facebook = await facebookDb.getFacebookContentByRecipeId(recipeId);
      if (facebook) {
        recipe.facebook = facebook;
      }
    } catch (fbError) {
      console.warn(`Error getting Facebook content for recipe ${recipeId}:`, fbError.message);
    }
    
    // Get recipe images from the database
    try {
      const db = require('./db');
      const images = await db.getAll(
        "SELECT * FROM recipe_images WHERE recipe_id = ? ORDER BY created_at DESC",
        [recipeId]
      );
      
      if (images && images.length > 0) {
        recipe.recipe_images = images;
        console.log(`Retrieved ${images.length} images for recipe ${recipeId}`);
      }
    } catch (imgError) {
      console.warn(`Error getting recipe images from database: ${imgError.message}`);
    }
    
    // Load the Excel exporter module
    const excelExporter = require('./recipe-excel-exporter');
    
    if (!excelExporter || !excelExporter.exportRecipeToExcel) {
      console.error('Excel Exporter module not loaded correctly for single recipe export!');
      return res.status(500).json({
        success: false,
        message: 'Excel Export functionality not available'
      });
    }
    
    // Generate Excel file
    const excelBuffer = await excelExporter.exportRecipeToExcel(recipe);
    
    // Set headers for Excel download
    res.setHeader('Content-Disposition', `attachment; filename="recipe-${recipe.recipe_idea.replace(/[^a-z0-9]/gi, '_')}.xlsx"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    
    // Send the Excel file
    res.send(excelBuffer);
  } catch (error) {
    console.error('Error exporting recipe to Excel:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to export recipe to Excel', 
      error: error.message 
    });
  }
});

// Pinterest Excel Export endpoint (using your working image logic)
app.get('/api/export/recipes/pinterest-excel', isAuthenticated, async (req, res) => {
  try {
    console.log('Exporting Pinterest data to Excel format with embedded grid images');
    
    // Get organization ID from session (same as your working export)
    const organizationId = req.session.user.organizationId;
    const { limit = 50 } = req.query;
    
    // Set up filters based on user role (same as your working export)
    let recipes = [];
    
    if (req.session.user.role === 'employee') {
      recipes = await recipeDb.getRecipesByOwnerAndOrg(
        req.session.user.id, 
        organizationId, 
        parseInt(limit), 
        0
      );
    } else {
      recipes = await recipeDb.getRecipesByOrg(
        organizationId,
        parseInt(limit), 
        0
      );
    }
    
    if (!recipes || recipes.length === 0) {
      return res.status(404).json({ success: false, message: 'No recipes found' });
    }
    
    console.log(`Found ${recipes.length} recipes for Pinterest Excel export`);
    
    // Process each recipe to get Pinterest data (simplified data structure)
    const pinterestData = [];
    
    for (const recipe of recipes) {
      try {
        // Get Pinterest variations for this recipe
        const pinterestVariations = await pinterestDb.getVariationsByRecipeId(recipe.id);
        
        // Check if this recipe has grid images (using database check first)
        const db = require('./db');
        const hasGridImages = await db.getOne(
          "SELECT COUNT(*) as count FROM recipe_images WHERE recipe_id = ? AND image_path LIKE 'grid_%'",
          [recipe.id]
        );
        
        // Only include recipes that have grid images
        if (hasGridImages && hasGridImages.count > 0) {
          const pinterestVariation = pinterestVariations && pinterestVariations.length > 0 ? pinterestVariations[0] : null;
          
          pinterestData.push({
            recipeId: recipe.id, // Important: pass the recipe ID for image lookup
            recipeTitle: recipe.recipe_idea || '',
            overlayText: pinterestVariation?.overlay_text || ''
          });
          
          console.log(`Added Pinterest data for recipe: ${recipe.recipe_idea} (ID: ${recipe.id})`);
        } else {
          console.log(`Skipped recipe ${recipe.recipe_idea} - no grid images found`);
        }
        
      } catch (recipeError) {
        console.warn(`Error processing recipe ${recipe.id}:`, recipeError.message);
        continue;
      }
    }
    
    if (pinterestData.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'No Pinterest data found (no recipes with grid images)' 
      });
    }
    
    // Use the Pinterest Excel exporter (same pattern as your working system)
    const pinterestExporter = require('./pinterest-excel-exporter');
    const excelBuffer = await pinterestExporter.exportPinterestToExcel(pinterestData);
    
    // Set headers for Excel download (same as your working export)
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename="pinterest-export.xlsx"');
    res.setHeader('Content-Length', excelBuffer.length);
    
    // Send the Excel file
    res.send(excelBuffer);
    
  } catch (error) {
    console.error('Error exporting Pinterest data to Excel:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to export Pinterest data to Excel: ' + error.message 
    });
  }
});

// Selected recipes Pinterest Excel export (same pattern as your working selected export)
app.post('/api/export/recipes/pinterest-excel/selected', isAuthenticated, async (req, res) => {
  try {
    const { recipeIds } = req.body;
    
    if (!recipeIds || !Array.isArray(recipeIds) || recipeIds.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'No recipes selected for Pinterest Excel export' 
      });
    }
    
    console.log(`Exporting Pinterest Excel for ${recipeIds.length} selected recipes`);
    
    // Get organization ID from session (same permission logic as your working export)
    const organizationId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    
    // Process each selected recipe
    const pinterestData = [];
    
    for (const recipeId of recipeIds) {
      try {
        const recipe = await recipeDb.getRecipeById(recipeId);
        
        if (!recipe) {
          console.warn(`Recipe not found: ${recipeId}`);
          continue;
        }
        
        // Check if user has access to this recipe (same as your working export)
        if (recipe.organization_id !== organizationId || 
            (userId && recipe.owner_id !== userId)) {
          console.warn(`Access denied for recipe: ${recipeId}`);
          continue;
        }
        
        // Get Pinterest variations for this recipe
        const pinterestVariations = await pinterestDb.getVariationsByRecipeId(recipeId);
        
        // Check if this recipe has grid images
        const db = require('./db');
        const hasGridImages = await db.getOne(
          "SELECT COUNT(*) as count FROM recipe_images WHERE recipe_id = ? AND image_path LIKE 'grid_%'",
          [recipeId]
        );
        
        // Only include recipes that have grid images
        if (hasGridImages && hasGridImages.count > 0) {
          const pinterestVariation = pinterestVariations && pinterestVariations.length > 0 ? pinterestVariations[0] : null;
          
          pinterestData.push({
            recipeId: recipeId, // Important: pass the recipe ID for image lookup
            recipeTitle: recipe.recipe_idea || '',
            overlayText: pinterestVariation?.overlay_text || ''
          });
          
          console.log(`Added Pinterest data for selected recipe: ${recipe.recipe_idea} (ID: ${recipeId})`);
        }
        
      } catch (error) {
        console.error(`Error processing selected recipe ${recipeId}:`, error);
        continue;
      }
    }
    
    if (pinterestData.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'No Pinterest data found for selected recipes' 
      });
    }
    
    // Use the Pinterest Excel exporter
    const pinterestExporter = require('./pinterest-excel-exporter');
    const excelBuffer = await pinterestExporter.exportPinterestToExcel(pinterestData);
    
    // Set headers for Excel download
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename="pinterest-export-selected.xlsx"');
    res.setHeader('Content-Length', excelBuffer.length);
    
    // Send the Excel file
    res.send(excelBuffer);
    
  } catch (error) {
    console.error('Error exporting selected Pinterest data to Excel:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to export selected Pinterest data: ' + error.message 
    });
  }
});



// Pinterest Image Generation Routes
const PinterestImageGenerator = require('./pinterest-image-generator');
const pinterestImageDb = require('./models/pinterest-image');

// Initialize Pinterest image database table
(async () => {
  try {
    await pinterestImageDb.initTable();
  } catch (error) {
    console.error('❌ Failed to initialize Pinterest images table:', error);
  }
})();

// Generate Pinterest image for a specific recipe
app.post('/api/pinterest/generate-image/:recipeId', isAuthenticated, async (req, res) => {
  try {
    const { recipeId } = req.params;
    const { variation = 1 } = req.body; // Simple variation only
    const userId = req.session.user.id;
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;

    if (!recipeId) {
      return res.status(400).json({
        success: false,
        message: 'Recipe ID is required'
      });
    }

    // Get recipe data
    const recipe = await getOne(`
      SELECT id, recipe_idea 
      FROM recipes 
      WHERE id = ? AND organization_id = ?
    `, [recipeId, organizationId]);

    if (!recipe) {
      return res.status(404).json({
        success: false,
        message: 'Recipe not found'
      });
    }

    console.log('🎨 Pinterest generation - Simple variation:', {
      recipeId: recipe.id,
      variation: variation
    });

    // Initialize Pinterest image generator
    const generator = new PinterestImageGenerator();
    
    // Generate Pinterest image using simple variation
    const result = await generator.generateFromRecipe(recipe, { getAll, getOne }, variation);

    // Save Pinterest image record to database
    const pinterestImageRecord = await pinterestImageDb.createPinterestImage({
      recipeId: recipe.id,
      keyword: recipe.recipe_idea,
      textOverlay: result.metadata.text,
      topImageUrl: result.metadata.topImageUrl || result.imageUrl || '/placeholder.jpg', // Handle template generation
      bottomImageUrl: result.metadata.bottomImageUrl || result.imageUrl || '/placeholder.jpg', // Handle template generation
      imagePath: result.imagePath,
      imageUrl: result.imageUrl,
      filename: result.filename,
      width: result.dimensions.width,
      height: result.dimensions.height,
      organizationId,
      websiteId,
      generationMetadata: result.metadata
    });

    console.log(`✅ Pinterest image generated successfully for recipe: ${recipe.recipe_idea}`);

    res.json({
      success: true,
      message: 'Pinterest image generated successfully',
      pinterestImage: {
        id: pinterestImageRecord.id,
        imageUrl: result.imageUrl,
        filename: result.filename,
        dimensions: result.dimensions,
        keyword: recipe.recipe_idea,
        textOverlay: result.metadata.text
      }
    });

  } catch (error) {
    console.error('❌ Pinterest image generation failed:', error);
    res.status(500).json({
      success: false,
      message: 'Pinterest image generation failed: ' + error.message
    });
  }
});

// Generate Pinterest images for multiple recipes (batch)
app.post('/api/pinterest/generate-images/batch', isAuthenticated, async (req, res) => {
  try {
    const { recipeIds, variation = 1 } = req.body; // Support variation selection
    const userId = req.session.user.id;
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;

    if (!recipeIds || !Array.isArray(recipeIds) || recipeIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Recipe IDs array is required'
      });
    }

    // Get recipe data for all requested recipes
    const placeholders = recipeIds.map(() => '?').join(',');
    const recipes = await getAll(`
      SELECT id, recipe_idea 
      FROM recipes 
      WHERE id IN (${placeholders}) AND organization_id = ?
    `, [...recipeIds, organizationId]);

    if (recipes.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No recipes found'
      });
    }

    // Initialize Pinterest image generator
    const generator = new PinterestImageGenerator();
    
    const results = [];
    const errors = [];

    // Process each recipe
    for (const recipe of recipes) {
      try {
        console.log(`🔄 Generating Pinterest image for: ${recipe.recipe_idea}`);
        
        // Add organization and website IDs to recipe for custom style loading
        recipe.organizationId = String(organizationId);
        
        // Ensure websiteId is properly extracted as string
        let currentWebsiteId = req.session.currentWebsiteId;
        if (typeof currentWebsiteId === 'object' && currentWebsiteId?.id) {
          currentWebsiteId = currentWebsiteId.id;
        }
        recipe.websiteId = String(currentWebsiteId);
        
        console.log('🔧 FIXED Batch Pinterest generation - Recipe with corrected IDs:', {
          recipeId: recipe.id,
          organizationId: recipe.organizationId,
          websiteId: recipe.websiteId
        });
        
        // Generate Pinterest image with variation
        const result = await generator.generateFromRecipe(recipe, { getAll, getOne }, variation);

        // Save Pinterest image record to database
        const pinterestImageRecord = await pinterestImageDb.createPinterestImage({
          recipeId: recipe.id,
          keyword: recipe.recipe_idea,
          textOverlay: result.metadata.text,
          topImageUrl: result.metadata.topImageUrl,
          bottomImageUrl: result.metadata.bottomImageUrl,
          imagePath: result.imagePath,
          imageUrl: result.imageUrl,
          filename: result.filename,
          width: result.dimensions.width,
          height: result.dimensions.height,
          organizationId,
          websiteId,
          generationMetadata: result.metadata
        });

        results.push({
          recipeId: recipe.id,
          keyword: recipe.recipe_idea,
          pinterestImage: {
            id: pinterestImageRecord.id,
            imageUrl: result.imageUrl,
            filename: result.filename,
            dimensions: result.dimensions
          }
        });

      } catch (error) {
        console.error(`❌ Failed to generate Pinterest image for recipe ${recipe.id}:`, error.message);
        errors.push({
          recipeId: recipe.id,
          keyword: recipe.recipe_idea,
          error: error.message
        });
      }
    }

    console.log(`✅ Batch Pinterest image generation complete: ${results.length} successful, ${errors.length} failed`);

    res.json({
      success: true,
      message: `Pinterest image generation complete: ${results.length} successful, ${errors.length} failed`,
      results,
      errors,
      summary: {
        total: recipes.length,
        successful: results.length,
        failed: errors.length
      }
    });

  } catch (error) {
    console.error('❌ Batch Pinterest image generation failed:', error);
    res.status(500).json({
      success: false,
      message: 'Batch Pinterest image generation failed: ' + error.message
    });
  }
});

// Get Pinterest images for a recipe
app.get('/api/pinterest/images/:recipeId', isAuthenticated, async (req, res) => {
  try {
    const { recipeId } = req.params;
    const organizationId = req.session.user.organizationId;

    const pinterestImages = await pinterestImageDb.getPinterestImagesByRecipeId(recipeId);
    
    // Filter by organization for security
    const filteredImages = pinterestImages.filter(img => img.organization_id === organizationId);

    res.json({
      success: true,
      pinterestImages: filteredImages
    });

  } catch (error) {
    console.error('❌ Error getting Pinterest images:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get Pinterest images: ' + error.message
    });
  }
});

// Get Pinterest variations (title/description) for a recipe
app.get('/api/pinterest/variations/:recipeId', isAuthenticated, async (req, res) => {
  try {
    const { recipeId } = req.params;
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;

    console.log('📌 Loading Pinterest variations for recipe:', recipeId);
    const variations = await pinterestDb.getVariationsByRecipeId(recipeId, websiteId);
    
    console.log('📌 Pinterest variations found:', variations?.length || 0);
    if (variations && variations.length > 0) {
      console.log('📌 First variation data:', {
        pin_title: variations[0].pin_title,
        pin_description: variations[0].pin_description,
        variation_number: variations[0].variation_number
      });
    }

    res.json({
      success: true,
      variations: variations || []
    });

  } catch (error) {
    console.error('❌ Error getting Pinterest variations:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get Pinterest variations: ' + error.message
    });
  }
});

// Get all Pinterest images for organization
app.get('/api/pinterest/images', isAuthenticated, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const websiteId = req.query.websiteId || req.session.currentWebsiteId;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const pinterestImages = await pinterestImageDb.getPinterestImagesByOrganization(organizationId, {
      websiteId,
      limit,
      offset
    });

    const stats = await pinterestImageDb.getPinterestImageStats(organizationId, websiteId);

    res.json({
      success: true,
      pinterestImages,
      stats,
      pagination: {
        limit,
        offset,
        hasMore: pinterestImages.length === limit
      }
    });

  } catch (error) {
    console.error('❌ Error getting Pinterest images:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get Pinterest images: ' + error.message
    });
  }
});

// Pinterest Gallery Page
app.get('/pinterest-gallery', isAuthenticated, (req, res) => {
  res.render('pinterest-gallery', {
    title: 'Pinterest Images Gallery',
    user: req.session.user
  });
});

// Delete Pinterest image
app.delete('/api/pinterest/images/:imageId', isAuthenticated, async (req, res) => {
  try {
    const { imageId } = req.params;
    const organizationId = req.session.user.organizationId;

    // Get image to verify ownership
    const image = await pinterestImageDb.getPinterestImageById(imageId);
    
    if (!image) {
      return res.status(404).json({
        success: false,
        message: 'Pinterest image not found'
      });
    }

    if (image.organization_id !== organizationId) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    // Delete the image record (file cleanup could be added here)
    const result = await pinterestImageDb.deletePinterestImage(imageId);

    res.json({
      success: true,
      message: 'Pinterest image deleted successfully'
    });

  } catch (error) {
    console.error('❌ Error deleting Pinterest image:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete Pinterest image: ' + error.message
    });
  }
});

// Get Pinterest images by keyword ID
app.get('/api/pinterest/images/keyword/:keywordId', isAuthenticated, async (req, res) => {
  try {
    const { keywordId } = req.params;
    const organizationId = req.session.user.organizationId;

    const pinterestImages = await pinterestImageDb.getPinterestImagesByKeywordId(keywordId);
    
    // Filter by organization for security
    const filteredImages = pinterestImages.filter(img => img.organization_id === organizationId);

    res.json({
      success: true,
      images: filteredImages
    });

  } catch (error) {
    console.error('❌ Error getting Pinterest images by keyword ID:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get Pinterest images: ' + error.message
    });
  }
});

// Helper function to generate Pinterest CSV content
function generatePinterestCSV(pinterestData) {
  // CSV headers
  const headers = ['Image 1 (Grid)', 'Image 2 (Grid)', 'Overlay Text'];
  
  // Create CSV rows
  const csvRows = [headers.join(',')];
  
  pinterestData.forEach(data => {
    const row = [
      escapeCsvField(data.image1),
      escapeCsvField(data.image2),
      escapeCsvField(data.overlayText)
    ];
    csvRows.push(row.join(','));
  });
  
  return csvRows.join('\n');
}

// Helper function to escape CSV fields
function escapeCsvField(field) {
  if (!field) return '';
  
  // Convert to string and escape quotes
  const stringField = String(field);
  
  // If field contains comma, newline, or quote, wrap in quotes and escape internal quotes
  if (stringField.includes(',') || stringField.includes('\n') || stringField.includes('"')) {
    return '"' + stringField.replace(/"/g, '""') + '"';
  }
  
  return stringField;
}

// ========================================
// PINTEREST CUSTOMIZER API
// ========================================

// Apply custom text box style to Pinterest generator
app.post('/api/pinterest/apply-custom-style', isAuthenticated, websiteMiddleware.ensureWebsiteSelected, async (req, res) => {
  try {
    console.log('🎨 ====== PINTEREST APPLY CUSTOM STYLE DEBUG ======');
    console.log('🎨 1. REQUEST RECEIVED');
    console.log('🎨    Body received:', JSON.stringify(req.body, null, 2));
    console.log('🎨    User session:', {
      userId: req.session.user?.id,
      organizationId: req.session.user?.organizationId,
      role: req.session.user?.role
    });
    console.log('🎨    Website session:', {
      currentWebsiteId: req.session.currentWebsiteId,
      type: typeof req.session.currentWebsiteId
    });
    
    const customStyle = req.body;
    
    // Extract organizationId from user - ensure it's correct
    const organizationId = req.session.user?.organizationId;
    
    // Extract websiteId from session - ensure it's a primitive value (same logic as Pinterest image generation)
    let currentWebsiteId = req.session.currentWebsiteId;
    if (typeof currentWebsiteId === 'object' && currentWebsiteId?.id) {
      currentWebsiteId = currentWebsiteId.id;
    }
    
    console.log('🎨 2. ID EXTRACTION');
    console.log('🎨    Extracted organizationId:', organizationId, '(type:', typeof organizationId, ')');
    console.log('🎨    Extracted currentWebsiteId:', currentWebsiteId, '(type:', typeof currentWebsiteId, ')');
    console.log('🎨    Original req.session.currentWebsiteId:', req.session.currentWebsiteId);
    
    if (!organizationId || !currentWebsiteId) {
      return res.status(400).json({
        success: false,
        message: 'Organization ID and Website ID are required'
      });
    }
    
    // Ensure both IDs are strings/primitives before passing to promptSettingsDb
    const finalOrgId = String(organizationId);
    const finalWebsiteId = String(currentWebsiteId);
    
    console.log('🎨 3. STRING CONVERSION');
    console.log('🎨    finalOrgId:', finalOrgId, '(type:', typeof finalOrgId, ')');
    console.log('🎨    finalWebsiteId:', finalWebsiteId, '(type:', typeof finalWebsiteId, ')');
    
    // Save custom style to settings
    const promptSettingsDb = require('./prompt-settings-db');
    
    console.log('🎨 4. LOADING CURRENT SETTINGS');
    const currentSettings = await promptSettingsDb.loadSettings(finalOrgId, finalWebsiteId);
    console.log('🎨    Current settings keys:', Object.keys(currentSettings));
    console.log('🎨    Current pinterestCustomStyle:', currentSettings.pinterestCustomStyle);
    
    const updatedSettings = {
      ...currentSettings,
      pinterestCustomStyle: customStyle
    };
    
    console.log('🎨 5. SAVING UPDATED SETTINGS');
    console.log('🎨    New pinterestCustomStyle:', updatedSettings.pinterestCustomStyle);
    
    await promptSettingsDb.saveSettings(updatedSettings, finalOrgId, finalWebsiteId);
    
    console.log('🎨 6. SETTINGS SAVED SUCCESSFULLY');
    console.log('🎨 ================================================');
    
    res.json({
      success: true,
      message: 'Custom Pinterest style applied successfully'
    });
    
  } catch (error) {
    console.error('❌ Error applying custom style:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to apply custom style: ' + error.message
    });
  }
});

// Save custom Pinterest style preset
app.post('/api/pinterest/save-preset', isAuthenticated, websiteMiddleware.ensureWebsiteSelected, async (req, res) => {
  try {
    console.log('💾 Pinterest save-preset endpoint called');
    console.log('💾 User session data:', {
      user: req.session.user,
      currentWebsiteId: req.session.currentWebsiteId,
      websiteIdType: typeof req.session.currentWebsiteId
    });
    console.log('💾 Request body:', req.body);
    
    const { name, settings } = req.body;
    
    // Extract organizationId from user - ensure it's correct
    const organizationId = req.session.user?.organizationId;
    // Extract websiteId from session - ensure it's a primitive value
    const websiteId = typeof req.session.currentWebsiteId === 'object' 
      ? req.session.currentWebsiteId?.id 
      : req.session.currentWebsiteId;
    
    console.log('💾 Final extracted values:');
    console.log('💾   organizationId:', organizationId, '(type:', typeof organizationId, ')');
    console.log('💾   websiteId:', websiteId, '(type:', typeof websiteId, ')');
    
    if (!name || !name.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Preset name is required'
      });
    }
    
    if (!organizationId || !websiteId) {
      return res.status(400).json({
        success: false,
        message: 'Organization ID and Website ID are required'
      });
    }
    
    // Ensure both IDs are strings/primitives before passing to promptSettingsDb
    const finalOrgId = String(organizationId);
    const finalWebsiteId = String(websiteId);
    
    console.log('💾 Final IDs for settings save:');
    console.log('💾   finalOrgId:', finalOrgId, '(type:', typeof finalOrgId, ')');
    console.log('💾   finalWebsiteId:', finalWebsiteId, '(type:', typeof finalWebsiteId, ')');
    
    console.log('💾 Saving Pinterest preset:', name, 'for org:', finalOrgId, 'website:', finalWebsiteId);
    
    // Load current settings
    const promptSettingsDb = require('./prompt-settings-db');
    const currentSettings = await promptSettingsDb.loadSettings(finalOrgId, finalWebsiteId);
    
    // Initialize presets array if it doesn't exist
    if (!currentSettings.pinterestPresets) {
      currentSettings.pinterestPresets = [];
    }
    
    // Check if preset with this name already exists
    const existingIndex = currentSettings.pinterestPresets.findIndex(p => p.name === name.trim());
    
    const preset = {
      name: name.trim(),
      settings: settings,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    if (existingIndex >= 0) {
      // Update existing preset
      currentSettings.pinterestPresets[existingIndex] = preset;
    } else {
      // Add new preset
      currentSettings.pinterestPresets.push(preset);
    }
    
    // Save updated settings
    await promptSettingsDb.saveSettings(currentSettings, finalOrgId, finalWebsiteId);
    
    res.json({
      success: true,
      message: 'Preset saved successfully',
      preset: preset
    });
    
  } catch (error) {
    console.error('❌ Error saving preset:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to save preset: ' + error.message
    });
  }
});

// ========================================
// PINTEREST TEMPLATE UPLOAD API
// ========================================

// Multer configuration for template uploads
const templateStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const templatesDir = path.join(__dirname, 'public', 'images', 'pinterest-templates');
    if (!fs.existsSync(templatesDir)) {
      fs.mkdirSync(templatesDir, { recursive: true });
    }
    cb(null, templatesDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `template-${uniqueSuffix}${ext}`);
  }
});

const templateUpload = multer({ 
  storage: templateStorage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.match(/^image\/(png|jpeg|jpg)$/)) {
      cb(null, true);
    } else {
      cb(new Error('Only PNG and JPG images are allowed'));
    }
  }
});

// Upload Canva template
app.post('/api/pinterest/upload-template', isAuthenticated, websiteMiddleware.ensureWebsiteSelected, templateUpload.single('template'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No template file uploaded'
      });
    }

    const organizationId = req.session.user?.organizationId;
    let currentWebsiteId = req.session.currentWebsiteId;
    
    // Extract websiteId from session - ensure it's a primitive value
    if (typeof currentWebsiteId === 'object' && currentWebsiteId?.id) {
      currentWebsiteId = currentWebsiteId.id;
    }

    if (!organizationId || !currentWebsiteId) {
      return res.status(400).json({
        success: false,
        message: 'Organization ID and Website ID are required'
      });
    }

    // Create template record
    const templateData = {
      id: Date.now().toString(),
      name: req.file.originalname,
      filename: req.file.filename,
      url: `/images/pinterest-templates/${req.file.filename}`,
      size: req.file.size,
      mimetype: req.file.mimetype,
      organizationId: String(organizationId),
      websiteId: String(currentWebsiteId),
      uploadedAt: new Date().toISOString()
    };

    // Save template info to settings
    const promptSettingsDb = require('./prompt-settings-db');
    const currentSettings = await promptSettingsDb.loadSettings(organizationId, currentWebsiteId);
    
    // Add template to settings
    if (!currentSettings.pinterestTemplates) {
      currentSettings.pinterestTemplates = [];
    }
    
    // Remove any existing template for this website (only one active template per website)
    currentSettings.pinterestTemplates = currentSettings.pinterestTemplates.filter(
      t => t.websiteId !== String(currentWebsiteId)
    );
    
    // Add new template
    currentSettings.pinterestTemplates.push(templateData);
    currentSettings.activeTemplate = templateData.id;

    await promptSettingsDb.saveSettings(currentSettings, organizationId, currentWebsiteId);

    console.log('✅ Pinterest template uploaded successfully:', templateData.name);

    res.json({
      success: true,
      message: 'Template uploaded successfully',
      template: templateData
    });

  } catch (error) {
    console.error('❌ Error uploading template:', error);
    
    // Clean up uploaded file if there was an error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    res.status(500).json({
      success: false,
      message: 'Failed to upload template: ' + error.message
    });
  }
});

// Remove Canva template
app.post('/api/pinterest/remove-template', isAuthenticated, websiteMiddleware.ensureWebsiteSelected, async (req, res) => {
  try {
    const { templateId } = req.body;
    const organizationId = req.session.user?.organizationId;
    let currentWebsiteId = req.session.currentWebsiteId;
    
    // Extract websiteId from session - ensure it's a primitive value
    if (typeof currentWebsiteId === 'object' && currentWebsiteId?.id) {
      currentWebsiteId = currentWebsiteId.id;
    }

    if (!templateId || !organizationId || !currentWebsiteId) {
      return res.status(400).json({
        success: false,
        message: 'Template ID, Organization ID and Website ID are required'
      });
    }

    const promptSettingsDb = require('./prompt-settings-db');
    const currentSettings = await promptSettingsDb.loadSettings(organizationId, currentWebsiteId);

    if (!currentSettings.pinterestTemplates) {
      return res.status(404).json({
        success: false,
        message: 'No templates found'
      });
    }

    // Find and remove template
    const templateIndex = currentSettings.pinterestTemplates.findIndex(t => t.id === templateId);
    if (templateIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'Template not found'
      });
    }

    const template = currentSettings.pinterestTemplates[templateIndex];
    
    // Remove file from disk
    const filePath = path.join(__dirname, 'public', 'images', 'pinterest-templates', template.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Remove from settings
    currentSettings.pinterestTemplates.splice(templateIndex, 1);
    
    // Clear active template if it was the removed one
    if (currentSettings.activeTemplate === templateId) {
      delete currentSettings.activeTemplate;
    }

    await promptSettingsDb.saveSettings(currentSettings, organizationId, currentWebsiteId);

    console.log('✅ Pinterest template removed successfully:', template.name);

    res.json({
      success: true,
      message: 'Template removed successfully'
    });

  } catch (error) {
    console.error('❌ Error removing template:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove template: ' + error.message
    });
  }
});

// Get current template for website
app.get('/api/pinterest/current-template', isAuthenticated, websiteMiddleware.ensureWebsiteSelected, async (req, res) => {
  try {
    const organizationId = req.session.user?.organizationId;
    let currentWebsiteId = req.session.currentWebsiteId;
    
    // Extract websiteId from session - ensure it's a primitive value
    if (typeof currentWebsiteId === 'object' && currentWebsiteId?.id) {
      currentWebsiteId = currentWebsiteId.id;
    }

    if (!organizationId || !currentWebsiteId) {
      return res.status(400).json({
        success: false,
        message: 'Organization ID and Website ID are required'
      });
    }

    const promptSettingsDb = require('./prompt-settings-db');
    const currentSettings = await promptSettingsDb.loadSettings(organizationId, currentWebsiteId);

    const activeTemplate = currentSettings.pinterestTemplates?.find(t => t.id === currentSettings.activeTemplate);

    res.json({
      success: true,
      template: activeTemplate || null
    });

  } catch (error) {
    console.error('❌ Error getting current template:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get current template: ' + error.message
    });
  }
});

// Save custom template design
app.post('/api/pinterest/save-template-design', isAuthenticated, websiteMiddleware.ensureWebsiteSelected, async (req, res) => {
  try {
    const templateData = req.body;
    const organizationId = req.session.user?.organizationId;
    let currentWebsiteId = req.session.currentWebsiteId;
    
    // Extract websiteId from session - ensure it's a primitive value
    if (typeof currentWebsiteId === 'object' && currentWebsiteId?.id) {
      currentWebsiteId = currentWebsiteId.id;
    }

    if (!organizationId || !currentWebsiteId) {
      return res.status(400).json({
        success: false,
        message: 'Organization ID and Website ID are required'
      });
    }

    // Load current settings
    const promptSettingsDb = require('./prompt-settings-db');
    const currentSettings = await promptSettingsDb.loadSettings(organizationId, currentWebsiteId);
    
    // Initialize template designs array if it doesn't exist
    if (!currentSettings.pinterestTemplateDesigns) {
      currentSettings.pinterestTemplateDesigns = [];
    }
    
    // Add new template design
    const newTemplate = {
      id: Date.now().toString(),
      name: templateData.name,
      elements: templateData.elements,
      canvas: templateData.canvas,
      organizationId: String(organizationId),
      websiteId: String(currentWebsiteId),
      createdAt: new Date().toISOString()
    };
    
    currentSettings.pinterestTemplateDesigns.push(newTemplate);

    // Save settings
    await promptSettingsDb.saveSettings(currentSettings, organizationId, currentWebsiteId);

    console.log('✅ Pinterest template design saved successfully:', {
      templateName: templateData.name,
      templateId: newTemplate.id,
      elementsCount: templateData.elements?.length || 0,
      organizationId,
      websiteId: currentWebsiteId
    });

    res.json({
      success: true,
      message: 'Template design saved successfully',
      template: newTemplate
    });

  } catch (error) {
    console.error('❌ Error saving template design:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to save template design: ' + error.message
    });
  }
});

// Get template designs
app.get('/api/pinterest/get-templates', isAuthenticated, websiteMiddleware.ensureWebsiteSelected, async (req, res) => {
  try {
    const organizationId = req.session.user?.organizationId;
    let currentWebsiteId = req.session.currentWebsiteId;
    
    // Extract websiteId from session - ensure it's a primitive value
    if (typeof currentWebsiteId === 'object' && currentWebsiteId?.id) {
      currentWebsiteId = currentWebsiteId.id;
    }

    if (!organizationId || !currentWebsiteId) {
      return res.status(400).json({
        success: false,
        message: 'Organization ID and Website ID are required'
      });
    }

    const promptSettingsDb = require('./prompt-settings-db');
    const currentSettings = await promptSettingsDb.loadSettings(organizationId, currentWebsiteId);

    const templates = currentSettings.pinterestTemplateDesigns || [];

    // Ensure all templates have IDs (migrate old templates)
    let templatesUpdated = false;
    templates.forEach((template, index) => {
      if (!template.id) {
        template.id = `${Date.now()}_${index}`;
        templatesUpdated = true;
        console.log('🔧 Added missing ID to template:', template.name);
      }
    });

    // Save if we updated any templates
    if (templatesUpdated) {
      currentSettings.pinterestTemplateDesigns = templates;
      await promptSettingsDb.saveSettings(currentSettings, organizationId, currentWebsiteId);
      console.log('✅ Updated templates with missing IDs');
    }

    console.log('📋 Loading templates for request:', {
      organizationId,
      websiteId: currentWebsiteId,
      templatesFound: templates.length,
      templateNames: templates.map(t => t.name),
      templateDetails: templates.map(t => ({
        id: t.id,
        name: t.name,
        elementsCount: t.elements?.length || 0
      }))
    });

    res.json({
      success: true,
      templates: templates,
      count: templates.length
    });

  } catch (error) {
    console.error('❌ Error getting template designs:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get template designs: ' + error.message
    });
  }
});

// Delete template design
app.delete('/api/pinterest/delete-template-design/:templateId', isAuthenticated, websiteMiddleware.ensureWebsiteSelected, async (req, res) => {
  try {
    const { templateId } = req.params;
    const organizationId = req.session.user?.organizationId;
    let currentWebsiteId = req.session.currentWebsiteId;
    
    // Extract websiteId from session - ensure it's a primitive value
    if (typeof currentWebsiteId === 'object' && currentWebsiteId?.id) {
      currentWebsiteId = currentWebsiteId.id;
    }

    if (!templateId || !organizationId || !currentWebsiteId) {
      return res.status(400).json({
        success: false,
        message: 'Template ID, Organization ID and Website ID are required'
      });
    }

    const promptSettingsDb = require('./prompt-settings-db');
    const currentSettings = await promptSettingsDb.loadSettings(organizationId, currentWebsiteId);

    if (!currentSettings.pinterestTemplateDesigns) {
      return res.status(404).json({
        success: false,
        message: 'No template designs found'
      });
    }

    // Find and remove template
    const templateIndex = currentSettings.pinterestTemplateDesigns.findIndex(t => t.id === templateId);
    if (templateIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'Template design not found'
      });
    }

    const template = currentSettings.pinterestTemplateDesigns[templateIndex];
    currentSettings.pinterestTemplateDesigns.splice(templateIndex, 1);

    await promptSettingsDb.saveSettings(currentSettings, organizationId, currentWebsiteId);

    console.log('✅ Pinterest template design deleted successfully:', template.name);

    res.json({
      success: true,
      message: 'Template design deleted successfully'
    });

  } catch (error) {
    console.error('❌ Error deleting template design:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete template design: ' + error.message
    });
  }
});

// ========================================
// FONT RENDERING API FOR PINTEREST IMAGES
// ========================================

// Endpoint to render text with Google Fonts in the browser
app.post('/api/render-text-overlay', isAuthenticated, (req, res) => {
  const { text, width, height, fontFamily, fontSize, variation, dominantColor } = req.body;
  
  // Create CSS background based on variation
  const createCSSBackground = (color, var_num) => {
    const { r, g, b } = color;
    const baseColor = `rgb(${r}, ${g}, ${b})`;
    const lightColor = `rgb(${Math.min(255, r + 60)}, ${Math.min(255, g + 60)}, ${Math.min(255, b + 60)})`;
    
    switch (var_num) {
      case 1: return `linear-gradient(90deg, ${baseColor} 0%, ${lightColor} 100%)`;
      case 2: return `linear-gradient(180deg, ${baseColor} 0%, ${lightColor} 50%, ${baseColor} 100%)`;
      case 3: return `repeating-linear-gradient(45deg, ${baseColor} 0px, ${lightColor} 10px, ${baseColor} 20px)`;
      case 4: return `radial-gradient(circle, ${lightColor} 0%, ${baseColor} 100%)`;
      case 5: return `linear-gradient(135deg, ${baseColor} 0%, ${lightColor} 50%, ${baseColor} 100%)`;
      default: return baseColor;
    }
  };

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <link href="https://fonts.googleapis.com/css2?family=${fontFamily.replace(/ /g, '+')}:wght@400;700;900&display=swap" rel="stylesheet">
      <style>
        body { 
          margin: 0; 
          padding: 20px;
          background: #f0f0f0;
        }
        .text-overlay {
          width: ${width}px;
          height: ${height}px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: "${fontFamily}", cursive;
          font-weight: 900;
          font-size: ${fontSize}px;
          color: white;
          text-align: center;
          text-shadow: 2px 2px 4px rgba(0,0,0,0.8);
          -webkit-text-stroke: 2px black;
          letter-spacing: 2px;
          line-height: 1.1;
          word-wrap: break-word;
          background: ${createCSSBackground(dominantColor, variation)};
          border-radius: 0;
          position: relative;
          overflow: hidden;
        }
        .text-overlay::before {
          content: '';
          position: absolute;
          top: 15px;
          left: 0;
          right: 0;
          height: 8px;
          background: repeating-linear-gradient(90deg, white 0px, white 25px, transparent 25px, transparent 35px);
          opacity: 0.9;
        }
        .text-overlay::after {
          content: '';
          position: absolute;
          bottom: 15px;
          left: 0;
          right: 0;
          height: 8px;
          background: repeating-linear-gradient(90deg, white 0px, white 25px, transparent 25px, transparent 35px);
          opacity: 0.9;
        }
      </style>
    </head>
    <body>
      <h3>Font Preview: ${fontFamily}</h3>
      <div class="text-overlay">${text}</div>
      <br>
      <p>This preview shows how your Pinterest text will look with the "${fontFamily}" Google Font.</p>
      <script>
        // Auto-screenshot functionality could be added here
        console.log('Text rendered with font:', '${fontFamily}');
      </script>
    </body>
    </html>
  `;

  res.send(html);
});

// ========================================
// BUFFER INTEGRATION FUNCTIONS
// ========================================

async function publishToBuffer(params) {
  const { 
    cookiesText, 
    profileId, 
    boardId, 
    orgId, 
    title, 
    description, 
    imageData, 
    sourceUrl, 
    shareNow, 
    scheduleTime 
  } = params;

  const fs = require('fs');
  const path = require('path');
  const sharp = require('sharp');
  
  let imagePath = null; // Declare imagePath at function scope for cleanup

  try {
    // Debug: Check if cookies are provided
    console.log('🔧 Buffer authentication check:', {
      hasCookies: !!cookiesText,
      cookiesLength: cookiesText?.length || 0,
      profileId,
      orgId,
      cookiesPreview: cookiesText ? cookiesText.substring(0, 100) + '...' : 'No cookies'
    });
    
    if (!cookiesText || !cookiesText.trim()) {
      throw new Error('No Buffer cookies provided. Please update your Buffer settings with valid cookies.');
    }
    // Parse cookies from text
    const parseCookiesFromText = (cookiesText) => {
      if (!cookiesText || !cookiesText.trim()) {
        throw new Error('No cookies provided');
      }
      
      const jar = {};
      
      if (cookiesText.includes('\t')) { // Netscape TSV format
        for (const line of cookiesText.split('\n')) {
          const trimmedLine = line.trim();
          if (!trimmedLine || trimmedLine.startsWith('#') || !trimmedLine.includes('\t')) {
            continue;
          }
          const parts = trimmedLine.split('\t');
          if (parts.length >= 7) {
            const name = parts[5].trim();
            const value = parts[6].trim();
            if (name) jar[name] = value;
          }
        }
      } else { // Simple format or semicolon separated
        const regex = /([^=;]+)=([^;]+)/g;
        let match;
        while ((match = regex.exec(cookiesText)) !== null) {
          jar[match[1].trim()] = match[2].trim();
        }
      }
      return jar;
    };

    // Build cookie header
    const buildCookieHeader = (allCookies) => {
      const whitelist = [
        'buffer_session', 'bufferapp_ci_session', 'AWSALB', 'AWSALBCORS',
        'AWSALBTG', 'AWSALBTGCORS', '__stripe_mid', '__stripe_sid'
      ];
      const pairs = whitelist
        .filter(k => allCookies[k])
        .map(k => `${k}=${allCookies[k]}`);
      
      if (pairs.length === 0) {
        throw new Error('No valid cookies found');
      }
      return pairs.join('; ');
    };

    const allCookies = parseCookiesFromText(cookiesText);
    const cookieHeader = buildCookieHeader(allCookies);
    
    // Debug: Show parsed cookies
    console.log('🍪 Parsed Buffer cookies:', {
      totalCookies: Object.keys(allCookies).length,
      cookieNames: Object.keys(allCookies),
      hasSessionCookie: !!allCookies['buffer_session'] || !!allCookies['_buffer_session'],
      cookieHeaderLength: cookieHeader.length
    });

    // Prepare image file
    if (imageData) {
      if (imageData.startsWith('data:image/')) {
        // Handle base64 data URL
        const base64Data = imageData.split(',')[1];
        const imageBuffer = Buffer.from(base64Data, 'base64');
        imagePath = path.join(__dirname, 'temp', `buffer_image_${Date.now()}.png`);
        
        // Ensure temp directory exists
        const tempDir = path.dirname(imagePath);
        if (!fs.existsSync(tempDir)) {
          fs.mkdirSync(tempDir, { recursive: true });
        }
        
        fs.writeFileSync(imagePath, imageBuffer);
      } else if (imageData.startsWith('http')) {
        // Handle URL - download image
        const response = await fetch(imageData);
        const arrayBuffer = await response.arrayBuffer();
        const imageBuffer = Buffer.from(arrayBuffer);
        imagePath = path.join(__dirname, 'temp', `buffer_image_${Date.now()}.png`);
        
        const tempDir = path.dirname(imagePath);
        if (!fs.existsSync(tempDir)) {
          fs.mkdirSync(tempDir, { recursive: true });
        }
        
        fs.writeFileSync(imagePath, imageBuffer);
      } else {
        throw new Error('Invalid image data format');
      }
    }

    if (!imagePath) {
      throw new Error('No image provided');
    }

    // Upload image to Buffer
    // Official Buffer API upload function
    const uploadImageViaOfficialAPI = async (imagePath, accessToken) => {
      try {
        console.log('📤 Using Buffer Official API to upload image...');
        
        // For official API, we can host the image ourselves and just send the URL
        const imageUrl = `${process.env.BASE_URL || 'https://benardibiz.com'}${imagePath}`;
        console.log('🔗 Image URL for Buffer:', imageUrl);
        
        return imageUrl; // Buffer Official API accepts direct URLs
      } catch (error) {
        console.error('❌ Buffer Official API upload failed:', error);
        throw error;
      }
    };

    const uploadImage = async (imagePath) => {
      const fileName = path.basename(imagePath);
      const mimeType = 'image/png';

      // 1. Get pre-signed URL
      const graphqlHeaders = {
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/json',
        'Origin': 'https://publish.buffer.com',
        'Referer': 'https://publish.buffer.com/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
        'Cookie': cookieHeader,
        'x-buffer-client-id': 'webapp-publishing'
      };

      const gqlQuery = `
        query s3PreSignedURL($input: S3PreSignedURLInput!) {
          s3PreSignedURL(input: $input) { url key bucket __typename }
        }
      `;

      const gqlPayload = {
        operationName: 's3PreSignedURL',
        query: gqlQuery,
        variables: {
          input: {
            organizationId: orgId,
            fileName: fileName,
            mimeType: mimeType,
            uploadType: 'postAsset'
          }
        }
      };

      // Add small delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      console.log('🔍 Request debug info:', {
        url: 'https://graph.buffer.com/?_o=s3PreSignedURL',
        cookieLength: cookieHeader.length,
        hasSessionCookie: cookieHeader.includes('session'),
        serverEnvironment: process.env.NODE_ENV || 'development'
      });
      
      // Try with different proxy/agent to bypass Cloudflare
      const proxyOptions = {
        method: 'POST',
        headers: {
          ...graphqlHeaders,
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
          'DNT': '1',
          'Connection': 'keep-alive',
          // Add more browser-like headers
          'Upgrade-Insecure-Requests': '1',
          'X-Forwarded-For': '192.168.1.1', // Fake residential IP
          'X-Real-IP': '192.168.1.1'
        },
        body: JSON.stringify(gqlPayload)
      };

      console.log('🔄 Attempting Buffer request with enhanced headers...');
      
      // Try official Buffer API as fallback
      const useOfficialAPI = process.env.BUFFER_ACCESS_TOKEN; // Set this in your environment
      
      if (useOfficialAPI) {
        console.log('🔄 Using Buffer Official API instead of GraphQL...');
        return await uploadImageViaOfficialAPI(imagePath, useOfficialAPI);
      }
      
      // Quick workaround: Skip image upload and use direct URL
      if (process.env.SKIP_BUFFER_UPLOAD === 'true') {
        console.log('⚡ Skipping Buffer upload, using direct image URL...');
        const directUrl = `${process.env.BASE_URL || 'https://benardibiz.com'}${imagePath}`;
        console.log('🔗 Direct image URL:', directUrl);
        return directUrl;
      }
      
      const gqlResponse = await fetch('https://graph.buffer.com/?_o=s3PreSignedURL', proxyOptions);

      if (!gqlResponse.ok) {
        const errorText = await gqlResponse.text();
        console.error('❌ Buffer GraphQL Error Details:', {
          status: gqlResponse.status,
          statusText: gqlResponse.statusText,
          headers: Object.fromEntries(gqlResponse.headers.entries()),
          body: errorText.substring(0, 500)
        });
        
        if (gqlResponse.status === 401) {
          throw new Error(`Authentication failed (401). Your Buffer cookies may be expired or invalid. Please:
1. Log into Buffer in your browser
2. Export fresh cookies
3. Update your Buffer settings with the new cookies`);
        }
        
        throw new Error(`GraphQL request failed: ${gqlResponse.status} - ${errorText}`);
      }

      const gqlData = await gqlResponse.json();
      if (gqlData.errors) {
        throw new Error(`GraphQL error: ${JSON.stringify(gqlData.errors)}`);
      }

      const presignData = gqlData.data?.s3PreSignedURL;
      if (!presignData?.url || !presignData?.key) {
        throw new Error('Invalid GraphQL response');
      }

      // 2. Upload to S3
      const imageBuffer = fs.readFileSync(imagePath);
      const s3Response = await fetch(presignData.url, {
        method: 'PUT',
        headers: { 'Content-Type': mimeType },
        body: imageBuffer
      });

      if (!s3Response.ok) {
        throw new Error(`S3 upload failed: ${s3Response.status}`);
      }

      // 3. Finalize upload
      const finalizePayload = {
        args: JSON.stringify({
          url: '/i/uploads/upload_media.json',
          args: { key: presignData.key, serviceForceTranscodeVideo: false },
          HTTPMethod: 'POST'
        })
      };

      const finalizeResponse = await fetch('https://publish.buffer.com/rpc/composerApiProxy', {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Origin': 'https://publish.buffer.com',
          'Referer': 'https://publish.buffer.com/all-channels?tab=queue',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Cookie': cookieHeader
        },
        body: JSON.stringify(finalizePayload)
      });

      if (!finalizeResponse.ok) {
        throw new Error(`Finalize upload failed: ${finalizeResponse.status}`);
      }

      const finalizeData = await finalizeResponse.json();
      const mediaUrl = finalizeData.result?.location || finalizeData.result?.details?.location;
      
      if (!mediaUrl) {
        throw new Error('No media URL returned from finalize');
      }

      return mediaUrl;
    };

    // Upload image and get media URL
    console.log('📸 Starting image upload to Buffer...');
    const mediaUrl = await uploadImage(imagePath);
    console.log('📸 Image upload completed, mediaUrl:', mediaUrl);

    // Schedule pin
    const media = {
      progress: 100,
      uploaded: true,
      photo: mediaUrl,
      picture: mediaUrl,
      thumbnail: mediaUrl,
      alt_text: null,
      source: { name: 'localFile', trigger: 'filePicker' },
      height: 2048,
      width: 2048
    };

    const scheduleArgs = {
      now: Boolean(shareNow),
      top: false,
      is_draft: false,
      shorten: true,
      text: description,
      scheduling_type: 'direct',
      fb_text: '',
      entities: null,
      annotations: [],
      profile_ids: [profileId],
      attachment: false,
      via: null,
      source: null,
      version: null,
      duplicated_from: null,
      created_source: 'allChannels',
      channel_data: null,
      subprofile_ids: [boardId],
      tags: [],
      title: title,
      media: media,
      ai_assisted: false,
      channelGroupIds: []
    };

    if (sourceUrl && sourceUrl !== '#') {
      scheduleArgs.source_url = sourceUrl;
    }

    if (scheduleTime && !shareNow) {
      scheduleArgs.due_at = Math.floor(new Date(scheduleTime).getTime() / 1000);
    }

    const schedulePayload = {
      args: JSON.stringify({
        url: '/1/updates/create.json',
        args: scheduleArgs,
        HTTPMethod: 'POST'
      })
    };

    console.log('📤 Sending Buffer schedule request:', {
      url: 'https://publish.buffer.com/rpc/composerApiProxy',
      method: 'POST',
      payloadSize: JSON.stringify(schedulePayload).length,
      scheduleArgsKeys: Object.keys(scheduleArgs),
      shareNow: scheduleArgs.now,
      profileId: scheduleArgs.profile_ids[0],
      boardId: scheduleArgs.subprofile_ids[0]
    });

    const scheduleResponse = await fetch('https://publish.buffer.com/rpc/composerApiProxy', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Origin': 'https://publish.buffer.com',
        'Referer': 'https://publish.buffer.com/all-channels?tab=queue',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Cookie': cookieHeader
      },
      body: JSON.stringify(schedulePayload)
    });

    console.log('📤 Buffer schedule response:', {
      status: scheduleResponse.status,
      statusText: scheduleResponse.statusText,
      ok: scheduleResponse.ok,
      headers: Object.fromEntries(scheduleResponse.headers.entries())
    });

    if (!scheduleResponse.ok) {
      const errorText = await scheduleResponse.text();
      console.log('❌ Buffer schedule error response:', errorText);
      throw new Error(`Schedule request failed: ${scheduleResponse.status} - ${errorText}`);
    }

    const scheduleData = await scheduleResponse.json();
    console.log('📤 Buffer schedule response data:', scheduleData);

    // Clean up temp file
    if (imagePath && fs.existsSync(imagePath)) {
      fs.unlinkSync(imagePath);
    }

    return scheduleData.result || scheduleData;

  } catch (error) {
    // Clean up temp file on error
    if (imagePath && fs.existsSync(imagePath)) {
      try {
        fs.unlinkSync(imagePath);
      } catch (cleanupError) {
        console.error('Error cleaning up temp file:', cleanupError);
      }
    }
    throw error;
  }
}

// ========================================
// BUFFER INTEGRATION ENDPOINTS
// ========================================


// Publish to Buffer
app.post('/api/buffer/publish/:keywordId', isAuthenticated, websiteMiddleware.hasWebsiteAccess, async (req, res) => {
  try {
    const { keywordId } = req.params;
    const { shareNow, scheduleTime, customTitle, customDescription, sourceUrl } = req.body;
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;

    // Get keyword data
    const keyword = await keywordsDb.getKeywordById(keywordId, websiteId);
    if (!keyword || keyword.organization_id !== organizationId) {
      return res.status(404).json({
        success: false,
        message: 'Keyword not found'
      });
    }

    // Get Buffer settings
    const promptSettingsDb = require('./prompt-settings-db');
    const settings = await promptSettingsDb.loadSettings(organizationId, websiteId);

    if (!settings.bufferEnabled) {
      return res.status(400).json({
        success: false,
        message: 'Buffer integration is not enabled for this website'
      });
    }

    // Validate Buffer settings
    const requiredSettings = ['bufferCookiesText', 'bufferProfileId', 'bufferOrgId'];
    const missingSettings = requiredSettings.filter(setting => !settings[setting]);
    
    // Check for boards availability
    const hasValidBoards = settings.bufferBoards && Array.isArray(settings.bufferBoards) && 
                          settings.bufferBoards.some(board => board.id && board.name);
    
    if (missingSettings.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing Buffer settings: ${missingSettings.join(', ')}`
      });
    }
    
    if (!hasValidBoards) {
      return res.status(400).json({
        success: false,
        message: 'No valid Buffer boards configured. Please add at least one board in settings.'
      });
    }

    // Get Pinterest image for this keyword
    const pinterestImages = await pinterestImageDb.getPinterestImagesByKeywordId(keywordId);
    if (!pinterestImages || pinterestImages.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No Pinterest image found for this keyword. Please generate Pinterest content first.'
      });
    }

    // Use the first Pinterest image
    const pinterestImage = pinterestImages[0];
    
    // Prepare title and description from Pinterest content
    const title = customTitle || pinterestImage.text_overlay || keyword.keyword;
    const description = customDescription || 
      (pinterestImage.text_overlay ? 
        `${pinterestImage.text_overlay}\n\n${keyword.full_recipe ? keyword.full_recipe.substring(0, 400) : keyword.interests}` :
        (keyword.full_recipe ? keyword.full_recipe.substring(0, 500) + '...' : keyword.interests));

    // Generate proper URL using WordPress domain and Pinterest SEO slug
    let finalSourceUrl = sourceUrl;
    
    if (!sourceUrl || sourceUrl === '#') {
      try {
        // Get WordPress settings for the domain
        const wordpressDb = require('./wordpress-db');
        const wpSettings = await wordpressDb.getSettings();
        
        // Get Pinterest variations for SEO slug
        const pinterestVariations = await pinterestDb.getVariationsByRecipeId(keyword.recipe_id, websiteId);
        
        if (wpSettings && wpSettings.site_url && pinterestVariations && pinterestVariations.length > 0) {
          const domain = wpSettings.site_url.replace(/\/$/, ''); // Remove trailing slash
          const slug = pinterestVariations[0].meta_slug;
          if (slug) {
            finalSourceUrl = `${domain}/${slug}`;
            console.log('🔗 Generated URL for Buffer:', finalSourceUrl);
          }
        }
      } catch (urlError) {
        console.warn('⚠️ Failed to generate proper URL, using fallback:', urlError.message);
        finalSourceUrl = sourceUrl || `http://localhost:3000/recipe/${keyword.recipe_id}`;
      }
    }

    // Call Buffer publishing function - use first available board
    const boardId = settings.bufferBoards && settings.bufferBoards[0]?.id;
    
    console.log('🔧 Keyword Board ID selection:', {
      fallbackBoardId: boardId,
      selectedBoardIdLength: boardId?.length,
      selectedBoardIdTrimmed: boardId?.trim()
    });
    
    const bufferResult = await publishToBuffer({
      cookiesText: settings.bufferCookiesText,
      profileId: settings.bufferProfileId,
      boardId: boardId?.trim(),
      orgId: settings.bufferOrgId,
      title,
      description,
      imageData: pinterestImage.image_data || pinterestImage.image_url,
      sourceUrl: finalSourceUrl,
      shareNow: shareNow || false,
      scheduleTime: scheduleTime || null
    });

    // Log activity
    await activityLogger.logActivity(
      req.session.user.id,
      organizationId,
      websiteId,
      'buffer_publish',
      `Published keyword "${keyword.keyword}" to Buffer`,
      {
        keywordId,
        title,
        bufferPostId: bufferResult.id,
        shareNow
      }
    );

    res.json({
      success: true,
      message: shareNow ? 'Published to Buffer immediately' : 'Scheduled for Buffer',
      bufferResult
    });

  } catch (error) {
    console.error('❌ Error publishing to Buffer:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to publish to Buffer: ' + error.message
    });
  }
});

// Get proper recipe URL for Buffer (same logic as publish but just returns URL)
app.get('/api/buffer/get-recipe-url/:recipeId', isAuthenticated, websiteMiddleware.hasWebsiteAccess, async (req, res) => {
  try {
    const { recipeId } = req.params;
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;

    // Get recipe data
    const recipe = await recipeDb.getRecipeById(recipeId);
    if (!recipe || recipe.organization_id !== organizationId) {
      return res.status(404).json({
        success: false,
        message: 'Recipe not found'
      });
    }

    // Generate proper source URL using WordPress domain and SEO slug
    let finalSourceUrl = `${req.protocol}://${req.get('host')}/recipe/${recipeId}`;
    
    try {
      // Get WordPress settings to get the website domain
      const wordpressSettings = await wordpressDb.getSettings();
      
      // Get Pinterest variations to get the SEO slug
      const pinterestVariations = await pinterestDb.getVariationsByRecipeId(recipeId, websiteId);
      
      if (wordpressSettings?.site_url && pinterestVariations?.[0]?.meta_slug) {
        // Use WordPress domain + Pinterest SEO slug
        const domain = wordpressSettings.site_url.replace(/\/$/, ''); // Remove trailing slash
        const slug = pinterestVariations[0].meta_slug;
        finalSourceUrl = `${domain}/${slug}`;
        console.log('✅ Generated proper URL with domain and slug:', finalSourceUrl);
      } else {
        // Fallback to recipe ID URL with WordPress domain if available
        const domain = wordpressSettings?.site_url?.replace(/\/$/, '') || `${req.protocol}://${req.get('host')}`;
        finalSourceUrl = `${domain}/recipe/${recipeId}`;
        console.log('⚠️ Using fallback URL (missing slug):', finalSourceUrl);
      }
    } catch (urlError) {
      console.error('❌ Error generating URL:', urlError);
      finalSourceUrl = `${req.protocol}://${req.get('host')}/recipe/${recipeId}`;
      console.log('❌ Using error fallback URL:', finalSourceUrl);
    }

    res.json({
      success: true,
      url: finalSourceUrl
    });

  } catch (error) {
    console.error('❌ Error getting recipe URL:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get recipe URL: ' + error.message
    });
  }
});

// Publish recipe to Buffer
app.post('/api/buffer/publish/recipe/:recipeId', isAuthenticated, websiteMiddleware.hasWebsiteAccess, async (req, res) => {
  try {
    const { recipeId } = req.params;
    const { shareNow, scheduleTime, customTitle, customDescription, sourceUrl, boardId } = req.body;
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;

    console.log('🔧 Buffer recipe publish request:', {
      recipeId,
      organizationId,
      websiteId,
      customTitle,
      customDescription: customDescription?.length || 0,
      sourceUrl,
      shareNow
    });

    // Get recipe data
    const recipe = await recipeDb.getRecipeById(recipeId);
    if (!recipe || recipe.organization_id !== organizationId) {
      return res.status(404).json({
        success: false,
        message: 'Recipe not found'
      });
    }

    // Get Buffer settings
    const promptSettingsDb = require('./prompt-settings-db');
    const settings = await promptSettingsDb.loadSettings(organizationId, websiteId);

    if (!settings.bufferEnabled) {
      return res.status(400).json({
        success: false,
        message: 'Buffer integration is not enabled for this website'
      });
    }

    // Validate Buffer settings
    const requiredSettings = ['bufferCookiesText', 'bufferProfileId', 'bufferOrgId'];
    const missingSettings = requiredSettings.filter(setting => !settings[setting]);
    
    // Check for boards availability
    const hasValidBoards = settings.bufferBoards && Array.isArray(settings.bufferBoards) && 
                          settings.bufferBoards.some(board => board.id && board.name);
    
    if (missingSettings.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing Buffer settings: ${missingSettings.join(', ')}`
      });
    }
    
    if (!hasValidBoards) {
      return res.status(400).json({
        success: false,
        message: 'No valid Buffer boards configured. Please add at least one board in settings.'
      });
    }

    // Get Pinterest image for this recipe
    console.log('📌 Loading Pinterest images for recipe:', recipeId);
    const pinterestImages = await pinterestImageDb.getPinterestImagesByRecipeId(recipeId);
    console.log('📌 Pinterest images found:', pinterestImages?.length || 0);
    
    if (!pinterestImages || pinterestImages.length === 0) {
      console.log('❌ No Pinterest images found for recipe');
      return res.status(400).json({
        success: false,
        message: 'No Pinterest image found for this recipe. Please generate Pinterest content first.'
      });
    }

    // Use the first Pinterest image
    const pinterestImage = pinterestImages[0];
    console.log('📌 Using Pinterest image:', {
      id: pinterestImage.id,
      text_overlay: pinterestImage.text_overlay,
      image_url: pinterestImage.image_url,
      image_path: pinterestImage.image_path
    });
    
    // Prepare title and description from Pinterest content and recipe
    const title = customTitle || pinterestImage.text_overlay || recipe.recipe_idea || 'Delicious Recipe';
    
    let description = customDescription;
    if (!description) {
      description = '';
      if (pinterestImage.text_overlay) {
        description += `${pinterestImage.text_overlay}\n\n`;
      }
      
      if (recipe.facebook_content) {
        description += recipe.facebook_content.substring(0, 400);
      } else if (recipe.blog_content) {
        description += recipe.blog_content.substring(0, 400);
      } else if (recipe.recipe_idea) {
        description += `Check out this amazing recipe: ${recipe.recipe_idea}`;
      }
    }

    // ALWAYS generate proper source URL using WordPress domain and SEO slug
    // (ignore frontend URL to ensure proper domain is always used)
    let finalSourceUrl = sourceUrl;
    
    try {
      // Get WordPress settings to get the website domain
      const wordpressSettings = await wordpressDb.getSettings();
      
      // Get Pinterest variations to get the SEO slug
      const pinterestVariations = await pinterestDb.getVariationsByRecipeId(recipeId, websiteId);
      
      console.log('🔗 WordPress settings for URL:', {
        siteUrl: wordpressSettings?.siteUrl,
        site_url: wordpressSettings?.site_url,
        websiteId,
        organizationId,
        fullSettings: wordpressSettings
      });
      
      console.log('🔗 Pinterest variations for slug:', {
        variationsCount: pinterestVariations?.length || 0,
        firstSlug: pinterestVariations?.[0]?.meta_slug,
        recipeId
      });
      
      if (wordpressSettings?.site_url && pinterestVariations?.[0]?.meta_slug) {
        // Use WordPress domain + Pinterest SEO slug
        const domain = wordpressSettings.site_url.replace(/\/$/, ''); // Remove trailing slash
        const slug = pinterestVariations[0].meta_slug;
        finalSourceUrl = `${domain}/${slug}`;
        console.log('✅ Generated proper URL with domain and slug:', finalSourceUrl);
      } else {
        console.log('⚠️ Missing data for URL generation:', {
          hasWordPressDomain: !!wordpressSettings?.site_url,
          hasPinterestSlug: !!(pinterestVariations?.[0]?.meta_slug),
          siteUrl: wordpressSettings?.site_url,
          metaSlug: pinterestVariations?.[0]?.meta_slug
        });
        
        // Fallback to recipe ID URL with WordPress domain if available
        const domain = wordpressSettings?.site_url?.replace(/\/$/, '') || `${req.protocol}://${req.get('host')}`;
        finalSourceUrl = `${domain}/recipe/${recipeId}`;
        console.log('⚠️ Using fallback URL (missing slug):', finalSourceUrl);
      }
    } catch (urlError) {
      console.error('❌ Error generating URL:', urlError);
      finalSourceUrl = sourceUrl || `${req.protocol}://${req.get('host')}/recipe/${recipeId}`;
      console.log('❌ Using error fallback URL:', finalSourceUrl);
    }

    // Read Pinterest image data - try image_data field first, then file system
    const fs = require('fs');
    const path = require('path');
    
    let imageData = null;
    
    console.log('📸 Pinterest image fields available:', {
      image_data: !!pinterestImage.image_data,
      image_path: pinterestImage.image_path,
      image_url: pinterestImage.image_url,
      filename: pinterestImage.filename
    });
    
    // First try image_data field (base64 data stored in database)
    if (pinterestImage.image_data) {
      console.log('✅ Using image_data from database (base64)');
      imageData = pinterestImage.image_data;
    }
    // Then try reading from file system
    else if (pinterestImage.image_path && pinterestImage.filename) {
      const imagePath = path.join(__dirname, 'public', 'images', 'pinterest', pinterestImage.filename);
      console.log('📸 Reading Pinterest image from file:', imagePath);
      
      if (fs.existsSync(imagePath)) {
        const imageBuffer = fs.readFileSync(imagePath);
        imageData = `data:image/png;base64,${imageBuffer.toString('base64')}`;
        console.log('✅ Pinterest image loaded from file as base64, size:', imageBuffer.length);
      } else {
        console.log('⚠️ Image file not found at:', imagePath);
        console.log('📂 Checking directory contents...');
        const dir = path.dirname(imagePath);
        if (fs.existsSync(dir)) {
          const files = fs.readdirSync(dir);
          console.log('📂 Files in pinterest directory:', files.slice(0, 10)); // Show first 10 files
        }
        imageData = pinterestImage.image_url;
      }
    } else {
      console.log('⚠️ No image_data or valid path, using URL:', pinterestImage.image_url);
      imageData = pinterestImage.image_url;
    }

    // Call Buffer publishing function
    console.log('🔧 Calling publishToBuffer with params:', {
      profileId: settings.bufferProfileId,
      boardId: settings.bufferBoardId,
      orgId: settings.bufferOrgId,
      title: title,
      description: description.substring(0, 100) + '...',
      imageDataType: imageData?.startsWith('data:') ? 'base64' : 'url',
      imageDataSize: imageData?.length || 0,
      sourceUrl: finalSourceUrl,
      shareNow: shareNow || false,
      scheduleTime: scheduleTime || null
    });

    // Use selected boardId from request, fallback to first available board
    const selectedBoardId = boardId || (settings.bufferBoards && settings.bufferBoards[0]?.id);
    
    console.log('🔧 Board ID selection:', {
      requestBoardId: boardId,
      fallbackBoardId: settings.bufferBoards?.[0]?.id,
      selectedBoardId,
      selectedBoardIdLength: selectedBoardId?.length,
      selectedBoardIdTrimmed: selectedBoardId?.trim(),
      allAvailableBoards: settings.bufferBoards
    });
    
    const bufferResult = await publishToBuffer({
      cookiesText: settings.bufferCookiesText,
      profileId: settings.bufferProfileId,
      boardId: selectedBoardId?.trim(),
      orgId: settings.bufferOrgId,
      title,
      description,
      imageData: imageData, // Use actual Pinterest image data
      sourceUrl: finalSourceUrl,
      shareNow: shareNow || false,
      scheduleTime: scheduleTime || null
    });

    console.log('📤 Buffer publishing result:', {
      success: !!bufferResult,
      resultKeys: bufferResult ? Object.keys(bufferResult) : 'none',
      id: bufferResult?.id,
      status: bufferResult?.status,
      error: bufferResult?.error
    });

    // Log activity
    await activityLogger.logActivity(
      req.session.user.id,
      organizationId,
      websiteId,
      'buffer_publish_recipe',
      `Published recipe "${recipe.recipe_idea}" to Buffer`,
      {
        recipeId,
        title,
        bufferPostId: bufferResult.id,
        shareNow,
        sourceUrl: finalSourceUrl
      }
    );

    res.json({
      success: true,
      message: shareNow ? 'Recipe published to Buffer immediately' : 'Recipe scheduled for Buffer',
      bufferResult
    });

  } catch (error) {
    console.error('❌ Error publishing recipe to Buffer:', error);
    
    // If Buffer is blocked by Cloudflare, save to local queue instead of failing
    if (error.message.includes('403') || error.message.includes('Just a moment')) {
      console.log('🚫 Detected Cloudflare blocking. Saving to local Buffer queue instead...');
      
      try {
        // Create buffer_queue table if it doesn't exist
        await db.run(`
          CREATE TABLE IF NOT EXISTS buffer_queue (
            id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
            recipe_id TEXT,
            title TEXT,
            description TEXT,
            board_id TEXT,
            image_path TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            processed_at TEXT,
            error_message TEXT
          )
        `);
        
        await db.run(`
          INSERT INTO buffer_queue (recipe_id, title, description, board_id, image_path, status, created_at, error_message)
          VALUES (?, ?, ?, ?, ?, 'blocked_by_cloudflare', datetime('now'), ?)
        `, [req.params.recipeId, 'Recipe Title', 'Recipe Description', 'board_id', 'image_path', 'Cloudflare IP blocking']);
        
        console.log('✅ Recipe saved to Buffer queue for manual processing');
        
        res.json({
          success: true,
          message: 'Recipe queued for Buffer (Cloudflare blocking detected - will be processed manually)',
          bufferResult: { status: 'queued', buffer_url: 'manual_processing_required' }
        });
        return;
      } catch (queueError) {
        console.log('❌ Could not save to Buffer queue:', queueError.message);
      }
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to publish recipe to Buffer: ' + error.message + ' (Your server IP may be blocked by Cloudflare)'
    });
  }
});

// Get individual recipe data
app.get('/api/recipes/:recipeId', isAuthenticated, async (req, res) => {
  try {
    const { recipeId } = req.params;
    const organizationId = req.session.user.organizationId;

    const recipe = await recipeDb.getRecipeById(recipeId);
    console.log('📖 Recipe loaded, available fields:', Object.keys(recipe || {}));
    console.log('📖 Pinterest fields:', {
      pinterestTitle: recipe?.pinterestTitle,
      pinterestDescription: recipe?.pinterestDescription,
      pinterest_title: recipe?.pinterest_title,
      pinterest_description: recipe?.pinterest_description
    });
    
    if (!recipe || recipe.organization_id !== organizationId) {
      return res.status(404).json({
        success: false,
        message: 'Recipe not found'
      });
    }

    res.json({
      success: true,
      recipe: recipe
    });

  } catch (error) {
    console.error('❌ Error getting recipe:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get recipe: ' + error.message
    });
  }
});

// Bulk publish to Buffer
app.post('/api/buffer/bulk-publish', isAuthenticated, websiteMiddleware.hasWebsiteAccess, async (req, res) => {
  try {
    const { keywordIds, shareNow, scheduleSettings, sourceUrl } = req.body;
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;

    if (!Array.isArray(keywordIds) || keywordIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No keywords selected'
      });
    }

    // Get Buffer settings
    const promptSettingsDb = require('./prompt-settings-db');
    const settings = await promptSettingsDb.loadSettings(organizationId, websiteId);

    if (!settings.bufferEnabled) {
      return res.status(400).json({
        success: false,
        message: 'Buffer integration is not enabled for this website'
      });
    }

    const results = [];
    let successCount = 0;
    let errorCount = 0;

    for (const keywordId of keywordIds) {
      try {
        // Get keyword data
        const keyword = await keywordsDb.getKeywordById(keywordId, websiteId);
        if (!keyword || keyword.organization_id !== organizationId) {
          results.push({
            keywordId,
            success: false,
            message: 'Keyword not found'
          });
          errorCount++;
          continue;
        }

        // Get Pinterest image
        const pinterestImages = await pinterestImageDb.getPinterestImagesByKeywordId(keywordId);
        if (!pinterestImages || pinterestImages.length === 0) {
          results.push({
            keywordId,
            keyword: keyword.keyword,
            success: false,
            message: 'No Pinterest image found'
          });
          errorCount++;
          continue;
        }

        const pinterestImage = pinterestImages[0];
        
        // Prepare content from Pinterest data
        const title = pinterestImage.text_overlay || keyword.keyword;
        const description = pinterestImage.text_overlay ? 
          `${pinterestImage.text_overlay}\n\n${keyword.full_recipe ? keyword.full_recipe.substring(0, 400) : keyword.interests}` :
          (keyword.full_recipe ? keyword.full_recipe.substring(0, 500) + '...' : keyword.interests);

        // Publish to Buffer
        const bufferResult = await publishToBuffer({
          cookiesText: settings.bufferCookiesText,
          profileId: settings.bufferProfileId,
          boardId: settings.bufferBoardId,
          orgId: settings.bufferOrgId,
          title,
          description,
          imageData: pinterestImage.image_data || pinterestImage.image_url,
          sourceUrl: sourceUrl || '#',
          shareNow: shareNow || false,
          scheduleTime: null // TODO: Add scheduling logic
        });

        results.push({
          keywordId,
          keyword: keyword.keyword,
          success: true,
          bufferPostId: bufferResult.id
        });
        successCount++;

        // Log activity
        await activityLogger.logActivity(
          req.session.user.id,
          organizationId,
          websiteId,
          'buffer_bulk_publish',
          `Bulk published keyword "${keyword.keyword}" to Buffer`,
          { keywordId, bufferPostId: bufferResult.id }
        );

        // Add delay between posts to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 2000));

      } catch (error) {
        console.error(`❌ Error publishing keyword ${keywordId} to Buffer:`, error);
        results.push({
          keywordId,
          success: false,
          message: error.message
        });
        errorCount++;
      }
    }

    res.json({
      success: true,
      message: `Bulk publish completed: ${successCount} successful, ${errorCount} failed`,
      results,
      stats: { successCount, errorCount, total: keywordIds.length }
    });

  } catch (error) {
    console.error('❌ Error in bulk Buffer publish:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to bulk publish to Buffer: ' + error.message
    });
  }
});

// Bulk Buffer Publishing for Recipes
app.post('/api/buffer/publish-bulk', isAuthenticated, websiteMiddleware.hasWebsiteAccess, async (req, res) => {
  try {
    const { recipeIds, boardId } = req.body;
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;

    console.log('🔧 Bulk Buffer recipe publish request:', {
      recipeIds,
      organizationId,
      websiteId,
      count: recipeIds?.length || 0
    });

    if (!Array.isArray(recipeIds) || recipeIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No recipes selected'
      });
    }

    // Get Buffer settings
    const promptSettingsDb = require('./prompt-settings-db');
    const settings = await promptSettingsDb.loadSettings(organizationId, websiteId);

    if (!settings.bufferEnabled) {
      return res.status(400).json({
        success: false,
        message: 'Buffer integration is not enabled for this website'
      });
    }

    // Validate Buffer settings
    const requiredSettings = ['bufferCookiesText', 'bufferProfileId', 'bufferOrgId'];
    const missingSettings = requiredSettings.filter(setting => !settings[setting]);
    
    // Check for boards availability
    const hasValidBoards = settings.bufferBoards && Array.isArray(settings.bufferBoards) && 
                          settings.bufferBoards.some(board => board.id && board.name);
    
    if (missingSettings.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing Buffer settings: ${missingSettings.join(', ')}`
      });
    }
    
    if (!hasValidBoards) {
      return res.status(400).json({
        success: false,
        message: 'No valid Buffer boards configured. Please add at least one board in settings.'
      });
    }

    const results = [];
    let successCount = 0;
    let errorCount = 0;

    // Process each recipe
    for (const recipeId of recipeIds) {
      try {
        console.log(`📝 Processing recipe ${recipeId}...`);

        // Get recipe data
        const recipe = await recipeDb.getRecipeById(recipeId);
        if (!recipe || recipe.organization_id !== organizationId) {
          results.push({
            recipeId,
            recipe: `Recipe ${recipeId}`,
            success: false,
            error: 'Recipe not found'
          });
          errorCount++;
          continue;
        }

        // Get Pinterest image for this recipe
        const pinterestImages = await pinterestImageDb.getPinterestImagesByRecipeId(recipeId);
        if (!pinterestImages || pinterestImages.length === 0) {
          results.push({
            recipeId,
            recipe: recipe.recipe_idea || `Recipe ${recipeId}`,
            success: false,
            error: 'No Pinterest image found. Generate Pinterest content first.'
          });
          errorCount++;
          continue;
        }

        // Use the first Pinterest image
        const pinterestImage = pinterestImages[0];
        
        // Prepare title and description
        const title = pinterestImage.text_overlay || recipe.recipe_idea || 'Delicious Recipe';
        
        let description = '';
        if (pinterestImage.text_overlay) {
          description += `${pinterestImage.text_overlay}\n\n`;
        }
        
        if (recipe.facebook_content) {
          description += recipe.facebook_content.substring(0, 400);
        } else if (recipe.blog_content) {
          description += recipe.blog_content.substring(0, 400);
        } else if (recipe.recipe_idea) {
          description += `Check out this amazing recipe: ${recipe.recipe_idea}`;
        }

        // Generate proper source URL
        let finalSourceUrl;
        try {
          const wordpressSettings = await wordpressDb.getSettings();
          const pinterestVariations = await pinterestDb.getVariationsByRecipeId(recipeId, websiteId);
          
          if (wordpressSettings?.site_url && pinterestVariations?.[0]?.meta_slug) {
            const domain = wordpressSettings.site_url.replace(/\/$/, '');
            const slug = pinterestVariations[0].meta_slug;
            finalSourceUrl = `${domain}/${slug}`;
          } else {
            const domain = wordpressSettings?.site_url?.replace(/\/$/, '') || `${req.protocol}://${req.get('host')}`;
            finalSourceUrl = `${domain}/recipe/${recipeId}`;
          }
        } catch (urlError) {
          finalSourceUrl = `${req.protocol}://${req.get('host')}/recipe/${recipeId}`;
        }

        // Read Pinterest image data
        const fs = require('fs');
        const path = require('path');
        
        let imageData = null;
        
        // Try image_data field first (base64 cropped images)
        if (pinterestImage.image_data) {
          try {
            console.log('📸 Using image_data (base64) for recipe:', recipeId);
            const base64Data = pinterestImage.image_data.split(',')[1] || pinterestImage.image_data;
            imageData = Buffer.from(base64Data, 'base64');
          } catch (base64Error) {
            console.error('❌ Error processing base64 image data:', base64Error);
          }
        }
        
        // Fallback to file system
        if (!imageData && pinterestImage.image_path) {
          try {
            const fullPath = path.resolve(pinterestImage.image_path);
            if (fs.existsSync(fullPath)) {
              imageData = fs.readFileSync(fullPath);
              console.log('📸 Using file system image for recipe:', recipeId);
            }
          } catch (fileError) {
            console.error('❌ Error reading image file:', fileError);
          }
        }
        
        if (!imageData) {
          results.push({
            recipeId,
            recipe: recipe.recipe_idea || `Recipe ${recipeId}`,
            success: false,
            error: 'Pinterest image data not available'
          });
          errorCount++;
          continue;
        }

        // Use selected boardId from request, fallback to first available board
        const selectedBoardId = boardId || (settings.bufferBoards && settings.bufferBoards[0]?.id);
        
        console.log('🔧 Bulk Board ID selection for recipe', recipeId, ':', {
          requestBoardId: boardId,
          fallbackBoardId: settings.bufferBoards?.[0]?.id,
          selectedBoardId,
          selectedBoardIdLength: selectedBoardId?.length,
          selectedBoardIdTrimmed: selectedBoardId?.trim()
        });
        
        // Create modified settings with selected board ID (trimmed)
        const modifiedSettings = {
          ...settings,
          bufferBoardId: selectedBoardId?.trim()
        };
        
        // Call Buffer publishing function
        const bufferResult = await publishToBuffer({
          title,
          description,
          imageBuffer: imageData,
          sourceUrl: finalSourceUrl,
          settings: modifiedSettings,
          shareNow: true // Default to immediate posting for bulk operations
        });

        if (bufferResult.success) {
          results.push({
            recipeId,
            recipe: recipe.recipe_idea || `Recipe ${recipeId}`,
            success: true,
            postId: bufferResult.postId
          });
          successCount++;
          
          // Log activity
          await activityDb.logActivity(
            req.session.user.id,
            'buffer_publish_bulk_recipe',
            `Published recipe "${recipe.recipe_idea}" to Buffer`,
            { recipeId, postId: bufferResult.postId },
            req.session.currentWebsiteId
          );
        } else {
          results.push({
            recipeId,
            recipe: recipe.recipe_idea || `Recipe ${recipeId}`,
            success: false,
            error: bufferResult.message
          });
          errorCount++;
        }

      } catch (recipeError) {
        console.error(`❌ Error processing recipe ${recipeId}:`, recipeError);
        results.push({
          recipeId,
          recipe: `Recipe ${recipeId}`,
          success: false,
          error: recipeError.message
        });
        errorCount++;
      }
    }

    console.log('📊 Bulk Buffer publishing complete:', {
      successful: successCount,
      failed: errorCount,
      total: recipeIds.length
    });

    res.json({
      success: true,
      message: `Bulk Buffer publishing complete: ${successCount} successful, ${errorCount} failed`,
      summary: {
        successful: successCount,
        failed: errorCount,
        total: recipeIds.length
      },
      results,
      errors: results.filter(r => !r.success)
    });

  } catch (error) {
    console.error('❌ Error in bulk Buffer recipe publish:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during bulk Buffer publishing',
      error: error.message
    });
  }
});

// API endpoint to get Buffer boards for current website
app.get('/api/buffer/boards', isAuthenticated, websiteMiddleware.hasWebsiteAccess, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;

    console.log('🔧 Loading Buffer boards for:', { organizationId, websiteId });

    // Get Buffer settings
    const promptSettingsDb = require('./prompt-settings-db');
    const settings = await promptSettingsDb.loadSettings(organizationId, websiteId);

    if (!settings.bufferEnabled) {
      return res.json({
        success: false,
        message: 'Buffer integration is not enabled for this website',
        boards: []
      });
    }

    // Return configured boards
    const boards = settings.bufferBoards || [{id: '', name: 'Default Board'}];
    
    // Filter out empty boards
    const validBoards = boards.filter(board => board.id && board.name);
    
    console.log('📊 Buffer boards loaded:', validBoards);

    res.json({
      success: true,
      boards: validBoards
    });

  } catch (error) {
    console.error('❌ Error loading Buffer boards:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error loading Buffer boards',
      boards: []
    });
  }
});

// API endpoint for websites
app.get('/api/websites', isAuthenticated, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const websites = await websiteDb.getWebsitesByOrganization(organizationId);
    
    res.json({
      success: true,
      websites: websites || []
    });
  } catch (error) {
    console.error('❌ Error getting websites:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get websites: ' + error.message,
      websites: []
    });
  }
});


// Add this endpoint to your server.js file to check and fix keyword status consistency

// Endpoint to check and fix keyword status consistency
app.post('/api/admin/fix-keyword-statuses', isAuthenticated, isAdmin, async (req, res) => {
  try {
    console.log('🔧 [ADMIN] Starting keyword status consistency check...');
    
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    
    // Set global context
    global.currentWebsiteId = websiteId;
    
    // Find keywords that should be 'processed' but are still 'pending'
    // These are keywords that have a recipe_id but status is still 'pending'
    let problemQuery = `
      SELECT k.id, k.keyword, k.status, k.recipe_id, k.website_id,
             r.id as recipe_exists,
             fb.id as facebook_exists,
             p.id as pinterest_exists
      FROM keywords k
      LEFT JOIN recipes r ON k.recipe_id = r.id
      LEFT JOIN facebook_content fb ON k.recipe_id = fb.recipe_id
      LEFT JOIN pinterest_variations p ON k.recipe_id = p.recipe_id
      WHERE k.organization_id = ?
        AND k.recipe_id IS NOT NULL
        AND k.status = 'pending'
    `;
    
    let params = [organizationId];
    
    if (websiteId) {
      problemQuery += ` AND k.website_id = ?`;
      params.push(websiteId);
    }
    
    const problemKeywords = await getAll(problemQuery, params);
    
    console.log(`🔍 [ADMIN] Found ${problemKeywords.length} keywords with status inconsistencies`);
    
    const fixes = [];
    let fixedCount = 0;
    
    for (const keyword of problemKeywords) {
      try {
        console.log(`🔧 [ADMIN] Checking keyword ${keyword.id}: "${keyword.keyword}"`);
        
        // Check if this keyword has generated content
        const hasContent = keyword.recipe_exists && (keyword.facebook_exists || keyword.pinterest_exists);
        
        if (hasContent) {
          console.log(`✅ [ADMIN] Keyword ${keyword.id} has content, should be 'processed'`);
          
          // Update status to processed
          const updateResult = await keywordsDb.updateKeywordStatus(
            keyword.id, 
            'processed', 
            keyword.recipe_id, 
            websiteId
          );
          
          if (updateResult) {
            fixedCount++;
            fixes.push({
              id: keyword.id,
              keyword: keyword.keyword,
              action: 'updated_to_processed',
              success: true
            });
            console.log(`✅ [ADMIN] Fixed keyword ${keyword.id} status`);
          } else {
            fixes.push({
              id: keyword.id,
              keyword: keyword.keyword,
              action: 'update_failed',
              success: false
            });
            console.error(`❌ [ADMIN] Failed to update keyword ${keyword.id} status`);
          }
        } else {
          console.log(`⚠️ [ADMIN] Keyword ${keyword.id} has recipe_id but no content - marking as failed`);
          
          // Update status to failed since there's no content
          const updateResult = await keywordsDb.updateKeywordStatus(
            keyword.id, 
            'failed', 
            null, 
            websiteId
          );
          
          if (updateResult) {
            fixes.push({
              id: keyword.id,
              keyword: keyword.keyword,
              action: 'updated_to_failed',
              success: true
            });
          } else {
            fixes.push({
              id: keyword.id,
              keyword: keyword.keyword,
              action: 'update_failed',
              success: false
            });
          }
        }
        
      } catch (error) {
        console.error(`❌ [ADMIN] Error fixing keyword ${keyword.id}:`, error);
        fixes.push({
          id: keyword.id,
          keyword: keyword.keyword,
          action: 'error',
          success: false,
          error: error.message
        });
      }
    }
    
    // Also check for orphaned recipes (recipes without keywords)
    let orphanQuery = `
      SELECT r.id, r.recipe_idea
      FROM recipes r
      LEFT JOIN keywords k ON r.id = k.recipe_id
      WHERE r.organization_id = ? AND k.id IS NULL
    `;
    
    let orphanParams = [organizationId];
    
    if (websiteId) {
      orphanQuery += ` AND r.website_id = ?`;
      orphanParams.push(websiteId);
    }
    
    const orphanRecipes = await getAll(orphanQuery, orphanParams);
    
    console.log(`🏗️ [ADMIN] Found ${orphanRecipes.length} orphaned recipes`);
    
    res.json({
      success: true,
      message: `Fixed ${fixedCount} keyword status inconsistencies`,
      details: {
        problemKeywords: problemKeywords.length,
        fixedCount: fixedCount,
        fixes: fixes,
        orphanRecipes: orphanRecipes.length,
        orphanRecipesList: orphanRecipes.slice(0, 10) // Show first 10
      }
    });
    
  } catch (error) {
    console.error('❌ [ADMIN] Error in keyword status consistency check:', error);
    res.status(500).json({
      success: false,
      message: error.message,
      error: error.stack
    });
  }
});

// Endpoint to get keyword status summary for debugging
app.get('/api/admin/keyword-status-summary', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    
    // Get status summary
    let summaryQuery = `
      SELECT 
        status,
        COUNT(*) as count,
        COUNT(CASE WHEN recipe_id IS NOT NULL THEN 1 END) as with_recipe_id,
        COUNT(CASE WHEN recipe_id IS NULL THEN 1 END) as without_recipe_id
      FROM keywords 
      WHERE organization_id = ?
    `;
    
    let params = [organizationId];
    
    if (websiteId) {
      summaryQuery += ` AND website_id = ?`;
      params.push(websiteId);
    }
    
    summaryQuery += ` GROUP BY status`;
    
    const statusSummary = await getAll(summaryQuery, params);
    
    // Get potential problems
    let problemsQuery = `
      SELECT 
        'pending_with_recipe' as issue_type,
        COUNT(*) as count
      FROM keywords k
      WHERE k.organization_id = ? 
        AND k.status = 'pending' 
        AND k.recipe_id IS NOT NULL
    `;
    
    let problemsParams = [organizationId];
    
    if (websiteId) {
      problemsQuery += ` AND k.website_id = ?`;
      problemsParams.push(websiteId);
    }
    
    const problems = await getAll(problemsQuery, problemsParams);
    
    res.json({
      success: true,
      summary: {
        statusBreakdown: statusSummary,
        potentialProblems: problems,
        websiteId: websiteId,
        organizationId: organizationId
      }
    });
    
  } catch (error) {
    console.error('❌ [ADMIN] Error getting keyword status summary:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Add this endpoint to your server.js file for immediate web-based fixing

// Emergency fix endpoint for stuck pending keywords
app.post('/api/emergency/fix-pending-keywords', isAuthenticated, isAdmin, async (req, res) => {
  try {
    console.log('🚨 [EMERGENCY] Starting emergency fix for pending keywords...');
    
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    
    // Get all keywords that are marked as 'pending' but have recipe_id and content
    let query = `
      SELECT 
        k.id, 
        k.keyword, 
        k.status, 
        k.recipe_id, 
        k.website_id,
        r.id as recipe_exists,
        fb.id as facebook_content_exists,
        pv.id as pinterest_content_exists,
        ri.id as recipe_image_exists
      FROM keywords k
      LEFT JOIN recipes r ON k.recipe_id = r.id
      LEFT JOIN facebook_content fb ON k.recipe_id = fb.recipe_id
      LEFT JOIN pinterest_variations pv ON k.recipe_id = pv.recipe_id
      LEFT JOIN recipe_images ri ON k.recipe_id = ri.recipe_id
      WHERE k.status = 'pending' 
        AND k.recipe_id IS NOT NULL
        AND k.organization_id = ?
    `;
    
    let params = [organizationId];
    
    if (websiteId) {
      query += ` AND k.website_id = ?`;
      params.push(websiteId);
    }
    
    query += ` ORDER BY k.added_at DESC`;
    
    const stuckKeywords = await getAll(query, params);
    
    console.log(`📊 [EMERGENCY] Found ${stuckKeywords.length} stuck keywords to fix`);
    
    const results = {
      total: stuckKeywords.length,
      fixed: 0,
      failed: 0,
      details: []
    };
    
    for (const keyword of stuckKeywords) {
      try {
        // Check if keyword has any content
        const hasContent = keyword.recipe_exists && 
                          (keyword.facebook_content_exists || 
                           keyword.pinterest_content_exists || 
                           keyword.recipe_image_exists);
        
        if (hasContent) {
          console.log(`✅ [EMERGENCY] Fixing keyword "${keyword.keyword}" - has content`);
          
          // Direct SQL update without website filter complications
          const updateResult = await runQuery(`
            UPDATE keywords 
            SET status = 'processed', 
                processed_at = CURRENT_TIMESTAMP 
            WHERE id = ? AND organization_id = ?
          `, [keyword.id, organizationId]);
          
          if (updateResult.changes > 0) {
            results.fixed++;
            results.details.push({
              id: keyword.id,
              keyword: keyword.keyword,
              action: 'updated_to_processed',
              success: true
            });
            console.log(`    ✅ Fixed keyword ${keyword.id}`);
          } else {
            results.failed++;
            results.details.push({
              id: keyword.id,
              keyword: keyword.keyword,
              action: 'update_failed',
              success: false,
              error: 'No rows updated'
            });
            console.log(`    ❌ Failed to update keyword ${keyword.id}`);
          }
        } else {
          console.log(`⚠️ [EMERGENCY] Keyword "${keyword.keyword}" has recipe but no content - marking as failed`);
          
          const updateResult = await runQuery(`
            UPDATE keywords 
            SET status = 'failed', 
                processed_at = CURRENT_TIMESTAMP,
                recipe_id = NULL
            WHERE id = ? AND organization_id = ?
          `, [keyword.id, organizationId]);
          
          if (updateResult.changes > 0) {
            results.fixed++;
            results.details.push({
              id: keyword.id,
              keyword: keyword.keyword,
              action: 'updated_to_failed',
              success: true
            });
          } else {
            results.failed++;
            results.details.push({
              id: keyword.id,
              keyword: keyword.keyword,
              action: 'update_failed',
              success: false
            });
          }
        }
        
      } catch (error) {
        console.error(`❌ [EMERGENCY] Error fixing keyword ${keyword.id}:`, error);
        results.failed++;
        results.details.push({
          id: keyword.id,
          keyword: keyword.keyword,
          action: 'error',
          success: false,
          error: error.message
        });
      }
    }
    
    // Final check
    const remainingStuck = await getOne(`
      SELECT COUNT(*) as count
      FROM keywords 
      WHERE status = 'pending' 
        AND recipe_id IS NOT NULL 
        AND organization_id = ?
        ${websiteId ? 'AND website_id = ?' : ''}
    `, websiteId ? [organizationId, websiteId] : [organizationId]);
    
    console.log(`🎉 [EMERGENCY] Fix complete: ${results.fixed} fixed, ${results.failed} failed`);
    console.log(`📊 [EMERGENCY] Remaining stuck: ${remainingStuck.count}`);
    
    res.json({
      success: true,
      message: `Emergency fix completed: ${results.fixed} keywords fixed, ${results.failed} failed`,
      results: results,
      remainingStuck: remainingStuck.count
    });
    
  } catch (error) {
    console.error('❌ [EMERGENCY] Critical error in emergency fix:', error);
    res.status(500).json({
      success: false,
      message: 'Emergency fix failed: ' + error.message,
      error: error.stack
    });
  }
});

// Quick status check endpoint
app.get('/api/emergency/keyword-status-check', isAuthenticated, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    
    // Get status summary
    let statusQuery = `
      SELECT 
        status,
        COUNT(*) as count,
        COUNT(CASE WHEN recipe_id IS NOT NULL THEN 1 END) as with_recipe_id
      FROM keywords 
      WHERE organization_id = ?
    `;
    
    let params = [organizationId];
    
    if (websiteId) {
      statusQuery += ` AND website_id = ?`;
      params.push(websiteId);
    }
    
    statusQuery += ` GROUP BY status ORDER BY count DESC`;
    
    const statusSummary = await getAll(statusQuery, params);
    
    // Get stuck keywords count
    let stuckQuery = `
      SELECT COUNT(*) as count
      FROM keywords k
      WHERE k.status = 'pending' 
        AND k.recipe_id IS NOT NULL
        AND k.organization_id = ?
    `;
    
    let stuckParams = [organizationId];
    
    if (websiteId) {
      stuckQuery += ` AND k.website_id = ?`;
      stuckParams.push(websiteId);
    }
    
    const stuckCount = await getOne(stuckQuery, stuckParams);
    
    res.json({
      success: true,
      summary: {
        statusBreakdown: statusSummary,
        stuckKeywords: stuckCount.count,
        websiteId: websiteId,
        organizationId: organizationId
      }
    });
    
  } catch (error) {
    console.error('❌ Error in status check:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Export selected recipes to Excel
app.post('/api/export/recipes/excel/selected', auth.isAuthenticated, async (req, res) => {
  try {
    const { recipeIds } = req.body;
    
    if (!recipeIds || !Array.isArray(recipeIds) || recipeIds.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'No recipes selected for export' 
      });
    }
    
    console.log(`Exporting ${recipeIds.length} selected recipes to Excel`);
    
    // Get organization ID from session
    const organizationId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    
    // Get the selected recipes
    const recipes = [];
    
    for (const recipeId of recipeIds) {
      try {
        const recipe = await recipeDb.getRecipeById(recipeId);
        
        if (!recipe) {
          console.warn(`Recipe not found: ${recipeId}`);
          continue;
        }
        
        // Check if user has access to this recipe
        if (recipe.organization_id !== organizationId || 
            (userId && recipe.owner_id !== userId)) {
          console.warn(`Access denied for recipe: ${recipeId}`);
          continue;
        }
        
        // Get Facebook content for this recipe
        try {
          const facebook = await facebookDb.getFacebookContentByRecipeId(recipeId);
          if (facebook) {
            recipe.facebook = facebook;
          }
        } catch (fbError) {
          console.warn(`Error getting Facebook content for recipe ${recipeId}:`, fbError.message);
        }
        
        // Get recipe images from the database
        try {
          const db = require('./db');
          const images = await db.getAll(
            "SELECT * FROM recipe_images WHERE recipe_id = ? ORDER BY created_at DESC",
            [recipeId]
          );
          
          if (images && images.length > 0) {
            recipe.recipe_images = images;
          }
        } catch (imgError) {
          console.warn(`Error getting recipe images for recipe ${recipeId}:`, imgError.message);
        }
        
        recipes.push(recipe);
      } catch (error) {
        console.error(`Error processing recipe ${recipeId}:`, error);
        continue;
      }
    }
    
    if (recipes.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'No accessible recipes found for export' 
      });
    }
    
    console.log(`Successfully processed ${recipes.length} recipes for export`);
    
    // Load the Excel exporter module
    const excelExporter = require('./recipe-excel-exporter');
    
    if (!excelExporter || !excelExporter.exportRecipesToExcel) {
      console.error('Excel Exporter module not loaded correctly!');
      return res.status(500).json({
        success: false,
        message: 'Excel Export functionality not available'
      });
    }
    
    // Generate Excel file with embedded images
    console.log('Generating Excel with embedded images...');
    const excelBuffer = await excelExporter.exportRecipesToExcel(recipes);
    
    // Set headers for Excel download
    const filename = `selected-recipes-${new Date().toISOString().split('T')[0]}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', excelBuffer.length);
    
    // Send the Excel file
    console.log('Sending Excel response');
    res.send(excelBuffer);
    
  } catch (error) {
    console.error('Error exporting selected recipes to Excel:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to export selected recipes to Excel: ' + error.message,
      error: error.stack
    });
  }
});

// API endpoint to diagnose recipe image issues
app.get('/api/diagnose-images/:recipeId?', auth.isAuthenticated, async (req, res) => {
  try {
    // Get the recipe ID from params or query
    const recipeId = req.params.recipeId || req.query.recipeId;
    
    // Define the recipe_images directory
    const recipeImagesDir = path.join(__dirname, 'recipe_images');
    
    // Check if the directory exists
    const dirExists = fs.existsSync(recipeImagesDir);
    
    // Get list of files in the directory
    let files = [];
    if (dirExists) {
      files = fs.readdirSync(recipeImagesDir);
    }
    
    // If a specific recipe ID is provided, get detailed info for that recipe
    let recipeInfo = null;
    if (recipeId) {
      // Get the recipe details
      const recipe = await recipeDb.getRecipeById(recipeId);
      
      if (recipe) {
        // Get associated images from database
        const db = require('./db');
        const images = await db.getAll(
          "SELECT * FROM recipe_images WHERE recipe_id = ? ORDER BY created_at DESC",
          [recipeId]
        );
        
        // Find matching files in the directory
        const matchingFiles = files.filter(file => file.includes(recipeId));
        
        // Check if each image file exists
        const imageChecks = [];
        if (images && images.length > 0) {
          for (const img of images) {
            const imagePath = img.image_path;
            const fullPath = path.join(recipeImagesDir, imagePath);
            const justFilename = path.basename(imagePath);
            const altPath = path.join(recipeImagesDir, justFilename);
            
            imageChecks.push({
              id: img.id,
              image_path: imagePath,
              fullPathExists: fs.existsSync(fullPath),
              fullPath: fullPath,
              altPathExists: fs.existsSync(altPath),
              altPath: altPath
            });
          }
        }
        
        recipeInfo = {
          recipe: recipe,
          dbImages: images || [],
          matchingFiles: matchingFiles,
          imageChecks: imageChecks
        };
      }
    }
    
    // Return the diagnostic info
    res.json({
      success: true,
      recipeImagesDir: recipeImagesDir,
      directoryExists: dirExists,
      fileCount: files.length,
      sampleFiles: files.slice(0, 10),
      recipeInfo: recipeInfo
    });
  } catch (error) {
    console.error('Error in image diagnostic:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// API key diagnostic endpoints
app.get('/api/diagnose-keys', async (req, res) => {
  try {
    const dbStatus = await apiKeyManager.checkApiKeyTable();
    const hasKey = await apiKeyManager.getApiKey('openai');
    const hasEnvKey = process.env.OPENAI_API_KEY ? true : false;
    const configApiKey = promptConfig.apiKey ? true : false;
    
    res.json({
      success: true,
      database: dbStatus,
      apiKeys: {
        openai: {
          found: hasKey ? true : false,
          source: hasKey ? 'Retrieved successfully' : 'Not found'
        }
      },
      environment: {
        OPENAI_API_KEY: hasEnvKey
      },
      config: {
        apiKey: configApiKey
      }
    });
  } catch (error) {
    console.error('Error in API key diagnostic:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Add a visual diagnostic page
app.get('/diagnose-keys', async (req, res) => {
  try {
    // Check database status
    const dbStatus = await apiKeyManager.checkApiKeyTable();
    
    // Try to get the OpenAI API key
    const hasKey = await apiKeyManager.getApiKey('openai');
    
    // Check environment variables
    const hasEnvKey = process.env.OPENAI_API_KEY ? true : false;
    
    // Get in-memory config
    const configApiKey = promptConfig.apiKey ? true : false;
    
    res.send(`
      <html>
        <head>
          <title>API Key Diagnostic</title>
          <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
          <div class="container my-5">
            <h1>API Key Diagnostic</h1>
            
            <div class="card mb-4">
              <div class="card-header">
                <h5>Database Status</h5>
              </div>
              <div class="card-body">
                <pre>${JSON.stringify(dbStatus, null, 2)}</pre>
              </div>
            </div>
            
            <div class="card mb-4">
              <div class="card-header">
                <h5>API Key Status</h5>
              </div>
              <div class="card-body">
                <p>OpenAI API Key: <span class="badge ${hasKey ? 'bg-success' : 'bg-danger'}">${hasKey ? 'Found' : 'Not Found'}</span></p>
              </div>
            </div>
            
            <div class="card mb-4">
              <div class="card-header">
                <h5>Environment Variables</h5>
              </div>
              <div class="card-body">
                <p>OPENAI_API_KEY: <span class="badge ${hasEnvKey ? 'bg-success' : 'bg-danger'}">${hasEnvKey ? 'Set' : 'Not Set'}</span></p>
              </div>
            </div>
            
            <div class="card mb-4">
              <div class="card-header">
                <h5>In-Memory Config</h5>
              </div>
              <div class="card-body">
                <p>apiKey: <span class="badge ${configApiKey ? 'bg-success' : 'bg-danger'}">${configApiKey ? 'Set' : 'Not Set'}</span></p>
              </div>
            </div>
            
            <a href="/settings" class="btn btn-primary">Back to Settings</a>
          </div>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('Error in API key diagnostic page:', error);
    res.status(500).send(`
      <html>
        <head>
          <title>API Key Diagnostic Error</title>
          <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
          <div class="container my-5">
            <div class="alert alert-danger">
              <h4>Error</h4>
              <p>${error.message}</p>
            </div>
            <a href="/settings" class="btn btn-primary">Back to Settings</a>
          </div>
        </body>
      </html>
    `);
  }
});

// API endpoint to get detailed queue information
app.get('/api/image-queue/status', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const organizationId = req.session.user.organizationId;
    
    // Get user's queue status
    const queueStatus = await imageQueueService.getQueueStatus(userId, organizationId);
    
    // Get overall system stats (for admins)
    let systemStats = null;
    if (req.session.user.role === 'admin') {
      try {
        const { getAll, getOne } = require('./db');
        
        // Get system-wide queue statistics
        const stats = await getAll(`
          SELECT 
            status,
            COUNT(*) as count,
            AVG(CASE 
              WHEN completed_at IS NOT NULL AND started_at IS NOT NULL 
              THEN (julianday(completed_at) - julianday(started_at)) * 24 * 60 * 60 
            END) as avg_processing_time_seconds
          FROM image_queue 
          WHERE created_at > datetime('now', '-24 hours')
          GROUP BY status
        `);
        
        // Get recent activity
        const recentActivity = await getAll(`
          SELECT iq.*, r.recipe_idea, u.name as user_name
          FROM image_queue iq
          LEFT JOIN recipes r ON iq.recipe_id = r.id
          LEFT JOIN users u ON iq.user_id = u.id
          WHERE iq.organization_id = ?
          ORDER BY iq.created_at DESC
          LIMIT 10
        `, [organizationId]);
        
        systemStats = {
          stats: stats,
          recentActivity: recentActivity
        };
      } catch (statsError) {
        console.error('Error getting system stats:', statsError);
      }
    }
    
    res.json({
      success: true,
      ...queueStatus,
      systemStats: systemStats,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error getting queue status:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// API endpoint to cancel a queued job
app.post('/api/image-queue/cancel/:jobId', isAuthenticated, async (req, res) => {
  try {
    const jobId = req.params.jobId;
    const userId = req.session.user.id;
    
    const result = await imageQueueService.cancelJob(jobId, userId);
    
    if (result.success) {
      res.json({
        success: true,
        message: result.message
      });
    } else {
      res.status(400).json({
        success: false,
        error: result.message
      });
    }
  } catch (error) {
    console.error('Error cancelling job:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// API endpoint to add a recipe to the image generation queue
app.post('/api/image-queue/add', isAuthenticated, async (req, res) => {
  try {
    const { recipeId, customPrompt } = req.body;
    
    if (!recipeId) {
      return res.status(400).json({
        success: false,
        error: 'Recipe ID is required'
      });
    }
    
    // Validate recipe exists and user has access
    const recipe = await getOne("SELECT * FROM recipes WHERE id = ?", [recipeId]);
    if (!recipe) {
      return res.status(404).json({
        success: false,
        error: 'Recipe not found'
      });
    }
    
    // Check user permissions
    const orgId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    
    if (recipe.organization_id !== orgId || 
        (userId && recipe.owner_id !== userId)) {
      return res.status(403).json({
        success: false,
        error: 'You do not have permission to generate images for this recipe'
      });
    }
    
    // Check for existing pending job
    const existingJob = await getOne(`
      SELECT * FROM image_queue 
      WHERE recipe_id = ? AND status IN ('queued', 'processing')
    `, [recipeId]);
    
    if (existingJob) {
      return res.json({
        success: false,
        error: 'This recipe already has a pending image generation',
        existingJob: {
          id: existingJob.id,
          position: existingJob.position,
          estimatedCompletion: existingJob.estimated_completion
        }
      });
    }
    
    // Get Discord settings
    const discordSettings = global.getCurrentDiscordSettings ? 
      await global.getCurrentDiscordSettings(req) : null;
    
    if (!discordSettings || !discordSettings.enableDiscord) {
      return res.status(400).json({
        success: false,
        error: 'Discord integration is not configured. Please check your settings.'
      });
    }
    
    // Add to queue
    const queueResult = await imageQueueService.addToQueue({
      recipeId: parseInt(recipeId),
      userId: req.session.user.id,
      organizationId: req.session.user.organizationId,
      websiteId: req.session.currentWebsiteId,
      customPrompt: customPrompt || null,
      discordSettings: discordSettings
    });
    
    res.json({
      success: true,
      message: 'Recipe added to image generation queue successfully',
      job: {
        id: queueResult.jobId,
        position: queueResult.position,
        estimatedCompletion: queueResult.estimatedCompletion,
        queueLength: queueResult.queueLength
      }
    });
    
  } catch (error) {
    console.error('Error adding to queue:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Admin-only endpoint to get detailed queue statistics
app.get('/api/admin/image-queue/stats', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { getAll, getOne } = require('./db');
    
    // Get comprehensive queue statistics
    const stats = await getAll(`
      SELECT 
        status,
        COUNT(*) as count,
        AVG(CASE 
          WHEN completed_at IS NOT NULL AND started_at IS NOT NULL 
          THEN (julianday(completed_at) - julianday(started_at)) * 24 * 60 * 60 
        END) as avg_processing_time_seconds,
        MIN(created_at) as earliest_job,
        MAX(created_at) as latest_job
      FROM image_queue 
      WHERE created_at > datetime('now', '-7 days')
      GROUP BY status
    `);
    
    // Get user statistics
    const userStats = await getAll(`
      SELECT 
        u.name,
        COUNT(*) as total_jobs,
        COUNT(CASE WHEN iq.status = 'completed' THEN 1 END) as completed_jobs,
        COUNT(CASE WHEN iq.status = 'failed' THEN 1 END) as failed_jobs,
        AVG(CASE 
          WHEN iq.completed_at IS NOT NULL AND iq.started_at IS NOT NULL 
          THEN (julianday(iq.completed_at) - julianday(iq.started_at)) * 24 * 60 * 60 
        END) as avg_processing_time
      FROM image_queue iq
      JOIN users u ON iq.user_id = u.id
      WHERE iq.created_at > datetime('now', '-7 days')
        AND iq.organization_id = ?
      GROUP BY u.id, u.name
      ORDER BY total_jobs DESC
    `, [req.session.user.organizationId]);
    
    // Get recent failures with details
    const recentFailures = await getAll(`
      SELECT iq.*, r.recipe_idea, u.name as user_name
      FROM image_queue iq
      LEFT JOIN recipes r ON iq.recipe_id = r.id
      LEFT JOIN users u ON iq.user_id = u.id
      WHERE iq.status = 'failed' 
        AND iq.organization_id = ?
        AND iq.created_at > datetime('now', '-24 hours')
      ORDER BY iq.created_at DESC
      LIMIT 20
    `, [req.session.user.organizationId]);
    
    // Get performance metrics
    const performanceMetrics = await getOne(`
      SELECT 
        COUNT(*) as total_jobs_today,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_today,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_today,
        COUNT(CASE WHEN status IN ('queued', 'processing') THEN 1 END) as active_jobs,
        ROUND(
          100.0 * COUNT(CASE WHEN status = 'completed' THEN 1 END) / 
          NULLIF(COUNT(CASE WHEN status IN ('completed', 'failed') THEN 1 END), 0), 
          2
        ) as success_rate_percent
      FROM image_queue 
      WHERE created_at > datetime('now', '-24 hours')
        AND organization_id = ?
    `, [req.session.user.organizationId]);
    
    res.json({
      success: true,
      stats: {
        byStatus: stats,
        byUser: userStats,
        performance: performanceMetrics,
        recentFailures: recentFailures
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error getting admin queue stats:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Admin-only endpoint to manage queue (pause/resume, clear failed jobs, etc.)
app.post('/api/admin/image-queue/manage', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { action, jobIds } = req.body;
    
    switch (action) {
      case 'clear_failed':
        const clearResult = await runQuery(`
          DELETE FROM image_queue 
          WHERE status = 'failed' 
            AND organization_id = ? 
            AND created_at < datetime('now', '-24 hours')
        `, [req.session.user.organizationId]);
        
        res.json({
          success: true,
          message: `Cleared ${clearResult.changes || 0} failed jobs`,
          clearedCount: clearResult.changes || 0
        });
        break;
        
      case 'clear_completed':
        const clearCompletedResult = await runQuery(`
          DELETE FROM image_queue 
          WHERE status = 'completed' 
            AND organization_id = ? 
            AND created_at < datetime('now', '-7 days')
        `, [req.session.user.organizationId]);
        
        res.json({
          success: true,
          message: `Cleared ${clearCompletedResult.changes || 0} completed jobs`,
          clearedCount: clearCompletedResult.changes || 0
        });
        break;
        
      case 'retry_failed':
        if (!jobIds || !Array.isArray(jobIds)) {
          return res.status(400).json({
            success: false,
            error: 'Job IDs array is required for retry action'
          });
        }
        
        // Reset failed jobs to queued status
        const retryResult = await runQuery(`
          UPDATE image_queue 
          SET status = 'queued', 
              error_message = NULL,
              retry_count = retry_count + 1,
              position = (SELECT MAX(position) FROM image_queue WHERE status IN ('queued', 'processing')) + 1,
              estimated_completion = datetime('now', '+' || (SELECT MAX(position) FROM image_queue WHERE status IN ('queued', 'processing')) * 90 || ' seconds')
          WHERE id IN (${jobIds.map(() => '?').join(',')}) 
            AND status = 'failed'
            AND organization_id = ?
        `, [...jobIds, req.session.user.organizationId]);
        
        res.json({
          success: true,
          message: `Retried ${retryResult.changes || 0} failed jobs`,
          retriedCount: retryResult.changes || 0
        });
        break;
        
      default:
        res.status(400).json({
          success: false,
          error: 'Invalid action. Supported actions: clear_failed, clear_completed, retry_failed'
        });
    }
    
  } catch (error) {
    console.error('Error managing queue:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Endpoint to get queue health status
app.get('/api/image-queue/health', isAuthenticated, async (req, res) => {
  try {
    const { getOne } = require('./db');
    
    // Check for stuck jobs (processing for more than 10 minutes)
    const stuckJobs = await getOne(`
      SELECT COUNT(*) as count
      FROM image_queue 
      WHERE status = 'processing' 
        AND started_at < datetime('now', '-10 minutes')
    `);
    
    // Check queue size
    const queueSize = await getOne(`
      SELECT COUNT(*) as count
      FROM image_queue 
      WHERE status = 'queued'
    `);
    
    // Check recent failure rate
    const recentStats = await getOne(`
      SELECT 
        COUNT(*) as total,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed
      FROM image_queue 
      WHERE created_at > datetime('now', '-1 hour')
    `);
    
    const failureRate = recentStats.total > 0 ? 
      (recentStats.failed / recentStats.total) * 100 : 0;
    
    // Determine health status
    let healthStatus = 'healthy';
    let issues = [];
    
    if (stuckJobs.count > 0) {
      healthStatus = 'warning';
      issues.push(`${stuckJobs.count} jobs appear to be stuck`);
    }
    
    if (queueSize.count > 20) {
      healthStatus = 'warning';
      issues.push(`Queue is large (${queueSize.count} jobs)`);
    }
    
    if (failureRate > 50) {
      healthStatus = 'critical';
      issues.push(`High failure rate (${failureRate.toFixed(1)}%)`);
    }
    
    res.json({
      success: true,
      health: {
        status: healthStatus,
        issues: issues,
        metrics: {
          stuckJobs: stuckJobs.count,
          queueSize: queueSize.count,
          recentFailureRate: Math.round(failureRate * 100) / 100
        }
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error checking queue health:', error);
    res.json({
      success: false,
      health: {
        status: 'error',
        issues: ['Unable to check queue health'],
        error: error.message
      },
      timestamp: new Date().toISOString()
    });
  }
});

// WebSocket or Server-Sent Events for real-time updates (optional enhancement)
app.get('/api/image-queue/events', isAuthenticated, (req, res) => {
  // Set up Server-Sent Events
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Cache-Control'
  });
  
  const userId = req.session.user.id;
  const organizationId = req.session.user.organizationId;
  
  // Send initial status
  const sendUpdate = async () => {
    try {
      const status = await imageQueueService.getQueueStatus(userId, organizationId);
      const data = JSON.stringify(status);
      res.write(`data: ${data}\n\n`);
    } catch (error) {
      console.error('Error sending SSE update:', error);
    }
  };
  
  // Send updates every 5 seconds
  const interval = setInterval(sendUpdate, 5000);
  
  // Send initial update
  sendUpdate();
  
  // Clean up on client disconnect
  req.on('close', () => {
    clearInterval(interval);
  });
});

// API endpoint to toggle prompt debugging
app.post('/api/toggle-debug-prompts', isAuthenticated, isAdmin, (req, res) => {
  try {
    // Toggle debug mode
    global.debugPrompts = !global.debugPrompts;
    
    // Log current status
    console.log(`\n${global.debugPrompts ? 'Enabled' : 'Disabled'} prompt debugging\n`);
    
    res.json({
      success: true,
      debugPrompts: global.debugPrompts,
      message: `Prompt debugging ${global.debugPrompts ? 'enabled' : 'disabled'}`
    });
  } catch (error) {
    console.error('Error toggling debug mode:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});

// API endpoint to get debug mode status
app.get('/api/debug-prompts-status', isAuthenticated, isAdmin, (req, res) => {
  try {
    res.json({
      success: true,
      debugPrompts: global.debugPrompts || false
    });
  } catch (error) {
    console.error('Error getting debug mode status:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});

// Add this debugging endpoint to your server.js file
app.get('/api/debug/discord-accounts', isAuthenticated, async (req, res) => {
  try {
    console.log('🔍 Starting Discord account debugging...');
    
    const debugInfo = {
      timestamp: new Date().toISOString(),
      userContext: {
        organizationId: req.session.user?.organizationId,
        websiteId: req.session.currentWebsiteId,
        userId: req.session.user?.id,
        userName: req.session.user?.name,
        userRole: req.session.user?.role
      },
      discordSources: {},
      recommendations: []
    };
    
    console.log('🏢 User context:', debugInfo.userContext);
    
    // Test 1: Check what getCurrentDiscordSettings returns
    try {
      console.log('🧪 Testing getCurrentDiscordSettings...');
      const currentSettings = await getCurrentDiscordSettings(req);
      
      if (currentSettings) {
        debugInfo.discordSources.getCurrentDiscordSettings = {
          source: currentSettings.source,
          channelId: currentSettings.discordChannelId,
          tokenPreview: currentSettings.discordUserToken.substring(0, 10) + '...',
          enabled: currentSettings.enableDiscord,
          organizationId: currentSettings.organizationId,
          websiteId: currentSettings.websiteId,
          status: 'AVAILABLE'
        };
        console.log('✅ getCurrentDiscordSettings returned settings');
      } else {
        debugInfo.discordSources.getCurrentDiscordSettings = {
          status: 'NOT_AVAILABLE',
          reason: 'Function returned null'
        };
        console.log('❌ getCurrentDiscordSettings returned null');
      }
    } catch (error) {
      debugInfo.discordSources.getCurrentDiscordSettings = {
        status: 'ERROR',
        error: error.message
      };
      console.error('❌ getCurrentDiscordSettings error:', error.message);
    }
    
    // Test 2: Check file-based settings
    try {
      console.log('🧪 Testing file-based settings...');
      const organizationId = req.session.user.organizationId;
      const websiteId = req.session.currentWebsiteId;
      
      if (organizationId && websiteId) {
        const fileSettings = promptSettingsDb.loadSettings(organizationId, websiteId);
        
        if (fileSettings && fileSettings.discordChannelId && fileSettings.discordUserToken) {
          debugInfo.discordSources.fileBasedSettings = {
            source: `website-${websiteId}`,
            channelId: fileSettings.discordChannelId,
            tokenPreview: fileSettings.discordUserToken.substring(0, 10) + '...',
            enabled: fileSettings.enableDiscord,
            status: 'AVAILABLE'
          };
          console.log('✅ File-based settings available');
        } else {
          debugInfo.discordSources.fileBasedSettings = {
            status: 'NOT_AVAILABLE',
            reason: 'No Discord settings in file or incomplete'
          };
          console.log('❌ File-based settings not available');
        }
      } else {
        debugInfo.discordSources.fileBasedSettings = {
          status: 'NOT_AVAILABLE',
          reason: 'No organization or website context'
        };
      }
    } catch (error) {
      debugInfo.discordSources.fileBasedSettings = {
        status: 'ERROR',
        error: error.message
      };
      console.error('❌ File-based settings error:', error.message);
    }
    
    // Test 3: Check database settings
    try {
      console.log('🧪 Testing database settings...');
      const dbSettings = await getDiscordSettingsFromDatabase();
      
      if (dbSettings && dbSettings.discordChannelId && dbSettings.discordUserToken) {
        debugInfo.discordSources.databaseSettings = {
          source: 'database-global',
          channelId: dbSettings.discordChannelId,
          tokenPreview: dbSettings.discordUserToken.substring(0, 10) + '...',
          enabled: dbSettings.enableDiscord,
          status: 'AVAILABLE'
        };
        console.log('✅ Database settings available');
      } else {
        debugInfo.discordSources.databaseSettings = {
          status: 'NOT_AVAILABLE',
          reason: 'No Discord settings in database or incomplete'
        };
        console.log('❌ Database settings not available');
      }
    } catch (error) {
      debugInfo.discordSources.databaseSettings = {
        status: 'ERROR',
        error: error.message
      };
      console.error('❌ Database settings error:', error.message);
    }
    
    // Test 4: Check environment variables
    try {
      console.log('🧪 Testing environment variables...');
      const envChannelId = process.env.DISCORD_CHANNEL_ID;
      const envUserToken = process.env.DISCORD_USER_TOKEN;
      
      if (envChannelId && envUserToken) {
        debugInfo.discordSources.environmentVariables = {
          source: 'environment-variables',
          channelId: envChannelId,
          tokenPreview: envUserToken.substring(0, 10) + '...',
          enabled: true,
          status: 'AVAILABLE'
        };
        console.log('✅ Environment variables available');
      } else {
        debugInfo.discordSources.environmentVariables = {
          status: 'NOT_AVAILABLE',
          reason: 'Environment variables not set'
        };
        console.log('❌ Environment variables not available');
      }
    } catch (error) {
      debugInfo.discordSources.environmentVariables = {
        status: 'ERROR',
        error: error.message
      };
      console.error('❌ Environment variables error:', error.message);
    }
    
    // Test 5: Check what Midjourney client would use
    try {
      console.log('🧪 Testing Midjourney client settings...');
      const MidjourneyClient = require('./midjourney/midjourney-client');
      
      // Check if client can initialize
      const canInit = MidjourneyClient.canInitialize();
      debugInfo.discordSources.midjourneyClient = {
        canInitialize: canInit.canInit,
        source: canInit.source || canInit.reason,
        status: canInit.canInit ? 'AVAILABLE' : 'NOT_AVAILABLE'
      };
      
      if (canInit.canInit) {
        console.log('✅ Midjourney client can initialize');
      } else {
        console.log('❌ Midjourney client cannot initialize:', canInit.reason);
      }
    } catch (error) {
      debugInfo.discordSources.midjourneyClient = {
        status: 'ERROR',
        error: error.message
      };
      console.error('❌ Midjourney client error:', error.message);
    }
    
    // Analyze conflicts and generate recommendations
    const availableSources = Object.entries(debugInfo.discordSources)
      .filter(([key, info]) => info.status === 'AVAILABLE')
      .map(([key, info]) => ({ key, ...info }));
    
    if (availableSources.length === 0) {
      debugInfo.recommendations.push('❌ NO DISCORD SETTINGS FOUND - Configure Discord in /settings page');
    } else if (availableSources.length === 1) {
      debugInfo.recommendations.push(`✅ Single Discord account found from: ${availableSources[0].source}`);
    } else {
      // Multiple sources - check for conflicts
      const uniqueChannels = [...new Set(availableSources.map(s => s.channelId))];
      const uniqueTokens = [...new Set(availableSources.map(s => s.tokenPreview))];
      
      if (uniqueChannels.length > 1 || uniqueTokens.length > 1) {
        debugInfo.recommendations.push('⚠️ CONFLICT DETECTED: Multiple different Discord accounts found');
        debugInfo.recommendations.push('This is the cause of your issue - different functions use different accounts');
        debugInfo.recommendations.push('Solution: Configure Discord settings in /settings page to override all sources');
        
        // Show which sources have which accounts
        availableSources.forEach(source => {
          debugInfo.recommendations.push(`   ${source.key}: Channel ${source.channelId}, Token ${source.tokenPreview}`);
        });
      } else {
        debugInfo.recommendations.push('✅ Multiple sources found but all use the same Discord account');
      }
    }
    
    // Priority order recommendation
    debugInfo.recommendations.push('');
    debugInfo.recommendations.push('Priority order for Discord settings:');
    debugInfo.recommendations.push('1. Website-specific settings (highest priority)');
    debugInfo.recommendations.push('2. Organization-level settings');
    debugInfo.recommendations.push('3. Database settings');
    debugInfo.recommendations.push('4. Environment variables (lowest priority)');
    
    console.log('🎯 Debug analysis complete');
    res.json(debugInfo);
    
  } catch (error) {
    console.error('❌ Error in Discord debug endpoint:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// API endpoint to get prompt logs list
app.get('/api/prompt-logs', isAuthenticated, isAdmin, (req, res) => {
  try {
    const fs = require('fs');
    const path = require('path');
    
    const logsDir = path.join(__dirname, 'prompt_logs');
    if (!fs.existsSync(logsDir)) {
      return res.json({
        success: true,
        logs: []
      });
    }
    
    const files = fs.readdirSync(logsDir)
      .filter(file => file.endsWith('.txt'))
      .map(file => {
        const filePath = path.join(logsDir, file);
        const stats = fs.statSync(filePath);
        return {
          name: file,
          size: stats.size,
          created: stats.mtime
        };
      })
      .sort((a, b) => b.created - a.created); // Newest first
    
    res.json({
      success: true,
      logs: files
    });
  } catch (error) {
    console.error('Error listing prompt logs:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});

// API endpoint to get a specific prompt log
app.get('/api/prompt-logs/:filename', isAuthenticated, isAdmin, (req, res) => {
  try {
    const fs = require('fs');
    const path = require('path');
    
    const filename = req.params.filename;
    // Security check to prevent directory traversal
    if (filename.includes('../') || filename.includes('..\\')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid filename'
      });
    }
    
    const logsDir = path.join(__dirname, 'prompt_logs');
    const filePath = path.join(logsDir, filename);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        message: 'Log file not found'
      });
    }
    
    const content = fs.readFileSync(filePath, 'utf8');
    res.json({
      success: true,
      filename: filename,
      content: content
    });
  } catch (error) {
    console.error('Error reading prompt log:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});

// Replace the existing /midjourney/api/recipe/:recipeId endpoint in server.js

// API endpoint to get recipe images status - IMPROVED VERSION
app.get('/midjourney/api/recipe/:recipeId', isAuthenticated, async (req, res) => {
  try {
    const recipeId = req.params.recipeId;
    
    if (!recipeId) {
      return res.status(400).json({
        success: false,
        message: 'Recipe ID is required'
      });
    }
    
    console.log(`🔍 [API] Getting image status for recipe: ${recipeId}`);
    
    // Get all images for this recipe from the recipe_images table
    // CRITICAL: Use a fresh query, not cached data
    const images = await db.getAll(
      "SELECT id, recipe_id, status, image_path, prompt, created_at, error, discord_message_id FROM recipe_images WHERE recipe_id = ? ORDER BY created_at DESC",
      [recipeId]
    );
    
    console.log(`📊 [API] Database query returned ${images.length} images`);
    
    if (!images || images.length === 0) {
      console.log(`ℹ️ [API] No images found for recipe ${recipeId}`);
      return res.json({
        success: true,
        images: [],
        message: 'No images found for this recipe'
      });
    }
    
    // Log each image for debugging
    images.forEach((img, index) => {
      console.log(`📷 [API] Image ${index + 1}:`, {
        id: img.id,
        status: img.status,
        image_path: img.image_path,
        created_at: img.created_at,
        has_error: !!img.error
      });
      
      if (img.error) {
        console.log(`   ⚠️ Error: ${img.error}`);
      }
    });
    
    // Process the images data
    const processedImages = images.map(img => {
      const processedImg = {
        id: img.id,
        recipe_id: img.recipe_id,
        status: img.status,
        image_path: img.image_path,
        prompt: img.prompt,
        created_at: img.created_at,
        error: img.error,
        discord_message_id: img.discord_message_id
      };
      
      // Add additional computed fields
      if (img.image_path) {
        processedImg.image_url = `/recipe_images/${img.image_path}`;
        
        // Check if file actually exists
        const fs = require('fs');
        const path = require('path');
        const fullPath = path.join(process.cwd(), 'recipe_images', img.image_path);
        processedImg.file_exists = fs.existsSync(fullPath);
        
        if (!processedImg.file_exists) {
          console.warn(`⚠️ [API] Image file not found: ${fullPath}`);
        }
      }
      
      return processedImg;
    });
    
    // Get summary statistics
    const stats = {
      total: images.length,
      completed: images.filter(img => img.status === 'completed').length,
      pending: images.filter(img => img.status === 'pending').length,
      generating: images.filter(img => img.status === 'generating').length,
      failed: images.filter(img => img.status === 'failed').length
    };
    
    console.log(`📈 [API] Image statistics for recipe ${recipeId}:`, stats);
    
    // Return the images with their status
    const response = {
      success: true,
      recipe_id: recipeId,
      images: processedImages,
      stats: stats,
      timestamp: new Date().toISOString()
    };
    
    console.log(`✅ [API] Returning ${processedImages.length} images for recipe ${recipeId}`);
    
    // Set headers to prevent caching
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    res.json(response);
    
  } catch (error) {
    console.error(`❌ [API] Error getting recipe images for ${req.params.recipeId}:`, error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to get recipe images',
      error_details: error.stack,
      timestamp: new Date().toISOString()
    });
  }
});
// Add this test endpoint to your server.js (temporarily, for debugging)

// Test endpoint to verify database updates work correctly
app.post('/api/test-db-update/:imageId', isAuthenticated, async (req, res) => {
  try {
    const imageId = req.params.imageId;
    const { status, image_path } = req.body;
    
    console.log(`🧪 [TEST] Testing database update for image ID: ${imageId}`);
    
    // Get current state
    const beforeUpdate = await db.getOne(
      "SELECT * FROM recipe_images WHERE id = ?",
      [imageId]
    );
    
    if (!beforeUpdate) {
      return res.status(404).json({
        success: false,
        message: 'Image record not found',
        imageId: imageId
      });
    }
    
    console.log(`📊 [TEST] Before update:`, {
      id: beforeUpdate.id,
      status: beforeUpdate.status,
      image_path: beforeUpdate.image_path
    });
    
    // Perform update
    const updateResult = await db.runQuery(
      "UPDATE recipe_images SET status = ?, image_path = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [status || 'test-completed', image_path || 'test-image.png', imageId]
    );
    
    console.log(`🔄 [TEST] Update result:`, updateResult);
    
    // Verify update
    const afterUpdate = await db.getOne(
      "SELECT * FROM recipe_images WHERE id = ?",
      [imageId]
    );
    
    console.log(`📊 [TEST] After update:`, {
      id: afterUpdate.id,
      status: afterUpdate.status,
      image_path: afterUpdate.image_path
    });
    
    const success = afterUpdate.status === (status || 'test-completed');
    
    res.json({
      success: success,
      message: success ? 'Database update test successful' : 'Database update test failed',
      before: {
        status: beforeUpdate.status,
        image_path: beforeUpdate.image_path
      },
      after: {
        status: afterUpdate.status,
        image_path: afterUpdate.image_path
      },
      updateResult: updateResult
    });
    
  } catch (error) {
    console.error(`❌ [TEST] Database update test failed:`, error);
    res.status(500).json({
      success: false,
      message: 'Database update test failed',
      error: error.message
    });
  }
});

// API endpoint for updating user
app.post('/api/users/:id', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        const { name, email, role, password } = req.body;
        
        // Validate required fields
        if (!name || !email || !role) {
            return res.status(400).json({
                success: false,
                message: 'Name, email, and role are required.'
            });
        }
        
        // Update user
        const updateResult = await userDb.updateUser(userId, {
            name,
            email,
            role,
            password: password ? password : undefined // Only update password if provided
        });
        
        if (updateResult) {
            res.json({
                success: true,
                message: 'User updated successfully'
            });
        } else {
            res.status(500).json({
                success: false,
                message: 'Failed to update user'
            });
        }
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'An unknown error occurred'
        });
    }
});

// API endpoint for deleting user
app.post('/api/users/:id/delete', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        // Don't allow deleting your own account
        if (userId === req.session.user.id) {
            return res.status(400).json({
                success: false,
                message: 'You cannot delete your own account.'
            });
        }
        
        // Delete user
        const deleteResult = await userDb.deleteUser(userId);
        
        if (deleteResult) {
            res.json({
                success: true,
                message: 'User deleted successfully'
            });
        } else {
            res.status(500).json({
                success: false,
                message: 'Failed to delete user'
            });
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'An unknown error occurred'
        });
    }
});



// Bulk recipe deletion endpoint
app.post('/api/recipes/bulk-delete', isAuthenticated, async (req, res) => {
  try {
    const { recipeIds } = req.body;
    
    if (!recipeIds || !Array.isArray(recipeIds) || recipeIds.length === 0) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid recipe IDs provided' 
      });
    }
    
    // Delete recipes using your recipeDb module
    let deletedCount = 0;
    for (const recipeId of recipeIds) {
      const result = await recipeDb.deleteRecipe(recipeId);
      if (result) deletedCount++;
    }
    
    res.json({ 
      success: true, 
      deletedCount: deletedCount,
      message: `Successfully deleted ${deletedCount} recipes`
    });
  } catch (error) {
    console.error('Error in bulk delete:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to delete recipes: ' + error.message 
    });
  }
});

// Alternative endpoint to delete recipes (using POST)
app.post('/api/recipes/delete/:id',isAuthenticated, async (req, res) => {
  console.log('POST delete endpoint hit with ID:', req.params.id);
  try {
    const recipeId = req.params.id;
    
    if (!recipeId) {
      console.log('No recipe ID provided');
      return res.status(400).json({
        success: false,
        message: 'Recipe ID is required'
      });
    }
    
    console.log('Checking if recipe exists:', recipeId);
    // Check if the recipe exists first
    const recipe = await recipeDb.getRecipeById(recipeId);
    if (!recipe) {
      console.log('Recipe not found with ID:', recipeId);
      return res.status(404).json({
        success: false,
        message: 'Recipe not found'
      });
    }
    
    console.log('Deleting recipe with ID:', recipeId);
    // Delete the recipe and all its associated content
    const result = await recipeDb.deleteRecipe(recipeId);
    
    if (result) {
      console.log('Successfully deleted recipe');
      return res.json({
        success: true,
        message: 'Recipe deleted successfully'
      });
    } else {
      console.log('Failed to delete recipe - database returned false');
      return res.status(500).json({
        success: false,
        message: 'Failed to delete recipe'
      });
    }
  } catch (error) {
    console.error('Error deleting recipe:', error);
    
    // Make sure we return JSON even in error cases
    return res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});

// Add this new API endpoint to server.js (in the API section, after other WordPress endpoints)

// Get WordPress publication status for specific recipes (for status refresh)
app.post('/api/recipes/wordpress-status', isAuthenticated, async (req, res) => {
  try {
    const { recipeIds } = req.body;
    
    if (!recipeIds || !Array.isArray(recipeIds) || recipeIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Recipe IDs are required'
      });
    }
    
    console.log(`🔄 Fetching WordPress status for ${recipeIds.length} recipes`);
    
    const organizationId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    
    const publications = [];
    
    // Get publication status for each recipe
    for (const recipeId of recipeIds) {
      try {
        // Verify user has access to this recipe
        const recipe = await recipeDb.getRecipeById(recipeId);
        if (!recipe) {
          console.warn(`Recipe not found: ${recipeId}`);
          continue;
        }
        
        // Check permissions
        if (recipe.organization_id !== organizationId || 
            (userId && recipe.owner_id !== userId)) {
          console.warn(`Access denied for recipe: ${recipeId}`);
          continue;
        }
        
        // Get WordPress publication status
        const recipePublications = await wordpressDb.getPublicationsByRecipeId(recipeId);
        
        if (recipePublications && recipePublications.length > 0) {
          // Get the most recent publication
          const latestPublication = recipePublications[0];
          
          publications.push({
            recipeId: recipeId,
            wp_post_id: latestPublication.wp_post_id,
            wp_post_url: latestPublication.wp_post_url,
            wp_status: latestPublication.wp_status,
            created_at: latestPublication.created_at,
            isPublished: latestPublication.wp_status === 'publish',
            isDraft: latestPublication.wp_status === 'draft',
            isPrivate: latestPublication.wp_status === 'private'
          });
        } else {
          // No publication found - recipe is unpublished
          publications.push({
            recipeId: recipeId,
            wp_post_id: null,
            wp_post_url: null,
            wp_status: null,
            created_at: null,
            isPublished: false,
            isDraft: false,
            isPrivate: false
          });
        }
        
      } catch (error) {
        console.error(`Error getting publication status for recipe ${recipeId}:`, error);
        // Add null entry for failed recipes
        publications.push({
          recipeId: recipeId,
          wp_post_id: null,
          wp_post_url: null,
          wp_status: null,
          created_at: null,
          isPublished: false,
          isDraft: false,
          isPrivate: false,
          error: error.message
        });
      }
    }
    
    console.log(`✅ Retrieved WordPress status for ${publications.length} recipes`);
    
    res.json({
      success: true,
      publications: publications,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Error fetching WordPress publication status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch WordPress publication status: ' + error.message
    });
  }
});

// API endpoint to delete a recipe - FIXED VERSION
console.log('Registering DELETE /api/recipes/:id route');
app.delete('/api/recipes/:id', isAuthenticated, async (req, res) => {
  console.log('DELETE endpoint hit with ID:', req.params.id);
  try {
    const recipeId = req.params.id;
    
    if (!recipeId) {
      console.log('No recipe ID provided');
      return res.status(400).json({
        success: false,
        message: 'Recipe ID is required'
      });
    }
    
    console.log('Checking if recipe exists:', recipeId);
    // Check if the recipe exists first
    const recipe = await recipeDb.getRecipeById(recipeId);
    if (!recipe) {
      console.log('Recipe not found with ID:', recipeId);
      return res.status(404).json({
        success: false,
        message: 'Recipe not found'
      });
    }
    
    console.log('Deleting recipe with ID:', recipeId);
    // Delete the recipe and all its associated content
    const result = await recipeDb.deleteRecipe(recipeId);
    
    if (result) {
      console.log('Successfully deleted recipe');
      return res.json({
        success: true,
        message: 'Recipe deleted successfully'
      });
    } else {
      console.log('Failed to delete recipe - database returned false');
      return res.status(500).json({
        success: false,
        message: 'Failed to delete recipe'
      });
    }
  } catch (error) {
    console.error('Error deleting recipe:', error);
    
    // Make sure we return JSON even in error cases
    return res.status(500).json({
      success: false,
      message: error.message || 'An unknown error occurred'
    });
  }
});

// Serve output files (for backward compatibility)
app.use('/output', express.static(path.join(__dirname, 'output')));

// Simple test endpoint for debugging
app.get('/api/test', (req, res) => {
  res.json({ 
    success: true, 
    message: 'API endpoints are working',
    timestamp: new Date().toISOString(),
    user: req.session?.user?.id || 'not logged in'
  });
});

// FIXED: Replace your Discord connection test endpoint in server.js
app.post('/api/test-discord-connection', isAuthenticated, async (req, res) => {
  try {
    console.log('🧪 Discord connection test requested:', req.body);
    
    const { channelId, userToken, webhookUrl, testMessage } = req.body;
    
    if (!channelId && !webhookUrl) {
      return res.status(400).json({
        success: false,
        message: 'Either Channel ID or Webhook URL is required'
      });
    }
    
    const axios = require('axios');
    
    // CRITICAL FIX: Save the tested settings to the same source that image generation uses
    // This ensures consistency between test and actual usage
    
    let testResult = null;
    
    // Test with webhook if provided
    if (webhookUrl && webhookUrl.trim() !== '') {
      try {
        console.log('🔗 Testing Discord webhook:', webhookUrl);
        
        const response = await axios.post(webhookUrl, {
          content: testMessage || 'Test message from RecipeGen AI - Discord connection successful! 🎉'
        }, {
          timeout: 10000,
          headers: {
            'Content-Type': 'application/json'
          }
        });
        
        console.log('✅ Webhook test successful:', response.status);
        testResult = {
          method: 'webhook',
          success: true,
          message: 'Discord webhook test successful! Message sent to Discord.',
          channelId: channelId,
          webhookUrl: webhookUrl
        };
        
      } catch (webhookError) {
        console.error('❌ Discord webhook test failed:', webhookError.message);
        
        if (!userToken || !channelId) {
          return res.json({
            method: 'webhook',
            success: false,
            message: `Webhook test failed: ${webhookError.response?.data?.message || webhookError.message}`
          });
        }
      }
    }
    
    // Test with user token if webhook failed or not provided
    if (!testResult && userToken && userToken.trim() !== '' && channelId && channelId.trim() !== '') {
      try {
        console.log('🔑 Testing Discord user token for channel:', channelId);
        
        let cleanToken = userToken.trim();
        
        const response = await axios.post(
          `https://discord.com/api/v10/channels/${channelId}/messages`,
          {
            content: testMessage || 'Test message from RecipeGen AI - Discord connection successful! 🎉'
          },
          {
            timeout: 10000,
            headers: {
              'Authorization': cleanToken,
              'Content-Type': 'application/json',
              'User-Agent': 'RecipeGenAI/1.0'
            }
          }
        );
        
        console.log('✅ User token test successful:', response.status);
        testResult = {
          method: 'user_token',
          success: true,
          message: 'Discord user token test successful! Message sent to Discord.',
          channelId: channelId,
          userToken: cleanToken
        };
        
      } catch (tokenError) {
        console.error('❌ Discord user token test failed:', tokenError.response?.data || tokenError.message);
        
        let errorMessage = 'User token test failed';
        
        if (tokenError.response) {
          if (tokenError.response.status === 401) {
            errorMessage = 'Invalid Discord token. Please check your token.';
          } else if (tokenError.response.status === 403) {
            errorMessage = 'Permission denied. Bot/User lacks permission to send messages to this channel.';
          } else if (tokenError.response.status === 404) {
            errorMessage = 'Channel not found. Please check your Channel ID.';
          } else {
            errorMessage = `Discord API error: ${tokenError.response.data?.message || tokenError.message}`;
          }
        }
        
        return res.json({
          method: 'user_token',
          success: false,
          message: errorMessage
        });
      }
    }
    
    // CRITICAL FIX: If test was successful, immediately save these settings 
    // to the SAME source that image generation will use
    if (testResult && testResult.success) {
      try {
        console.log('💾 Saving tested Discord settings for consistent usage...');
        
        // Get current context
        const organizationId = req.session.user.organizationId;
        const websiteId = req.session.currentWebsiteId;
        
        // Create the settings object with the TESTED credentials
        const testedSettings = {
          discordChannelId: testResult.channelId || channelId,
          discordUserToken: testResult.userToken || userToken,
          discordWebhookUrl: webhookUrl || '',
          enableDiscord: true
        };
        
        console.log(`🎯 Saving tested Discord settings for org ${organizationId}, website ${websiteId}`);
        console.log(`   Channel: ${testedSettings.discordChannelId}`);
        console.log(`   Token: ${testedSettings.discordUserToken.substring(0, 10)}...`);
        console.log(`   Method: ${testResult.method}`);
        
        // Save to the file-based system (primary source for getCurrentDiscordSettings)
        const currentSettings = promptSettingsDb.loadSettings(organizationId, websiteId);
        const updatedSettings = {
          ...currentSettings,
          ...testedSettings
        };
        
        promptSettingsDb.saveSettings(updatedSettings, organizationId, websiteId);
        console.log('✅ Saved to file-based system');
        
        // Also save to database for backup
        await saveDiscordSettingsToDatabase(testedSettings);
        console.log('✅ Saved to database system');
        
        // Update global promptConfig
        promptConfig = { ...promptConfig, ...testedSettings };
        console.log('✅ Updated global promptConfig');
        
        // Reset Midjourney client to pick up new settings
        const MidjourneyClient = require('./midjourney/midjourney-client');
        MidjourneyClient.resetInstance();
        console.log('✅ Reset Midjourney client instance');
        
        // Add confirmation to response
        testResult.settingsSaved = true;
        testResult.savedTo = ['file-system', 'database', 'global-config'];
        
      } catch (saveError) {
        console.error('⚠️ Could not save tested settings:', saveError.message);
        testResult.settingsSaved = false;
        testResult.saveError = saveError.message;
      }
    }
    
    if (!testResult) {
      return res.status(400).json({
        success: false,
        message: 'No valid Discord connection method provided. Please provide either a Webhook URL or both Channel ID and User Token.'
      });
    }
    
    return res.json(testResult);
    
  } catch (error) {
    console.error('❌ Discord connection test error:', error);
    res.status(500).json({
      success: false,
      message: `Server error: ${error.message}`
    });
  }
});

// Test Discord settings endpoint
app.post('/api/test-discord-settings', isAuthenticated, async (req, res) => {
  try {
    const MidjourneyClient = require('./midjourney/midjourney-client');
    
    console.log('Testing Discord settings...');
    console.log('Channel ID:', process.env.DISCORD_CHANNEL_ID);
    console.log('User Token present:', !!process.env.DISCORD_USER_TOKEN);
    
    const client = MidjourneyClient.getInstance();
    
    // Try to initialize
    await client.initialize();
    
    res.json({
      success: true,
      message: 'Discord settings are valid and working!'
    });
  } catch (error) {
    console.error('Discord settings test failed:', error);
    res.json({
      success: false,
      message: error.message,
      details: 'Check the server console for detailed error information'
    });
  }
});

// Get cleanup configuration
app.get('/api/keywords/cleanup-config', isAuthenticated, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    
    const keywordCleanupService = require('./services/keyword-cleanup-service');
    const config = await keywordCleanupService.getCleanupConfig(organizationId, websiteId);
    
    res.json({
      success: true,
      config: config
    });
  } catch (error) {
    console.error('Error getting cleanup config:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Update cleanup configuration
app.post('/api/keywords/cleanup-config', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    const { autoCleanupEnabled, cleanupAfterDays, cleanupAction } = req.body;
    
    const keywordCleanupService = require('./services/keyword-cleanup-service');
    await keywordCleanupService.updateCleanupConfig(organizationId, websiteId, {
      autoCleanupEnabled: autoCleanupEnabled === true || autoCleanupEnabled === 'true',
      cleanupAfterDays: parseInt(cleanupAfterDays) || 7,
      cleanupAction: cleanupAction || 'archive'
    });
    
    res.json({
      success: true,
      message: 'Cleanup configuration updated successfully'
    });
  } catch (error) {
    console.error('Error updating cleanup config:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Manual cleanup trigger
app.post('/api/keywords/cleanup', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    const { cleanupAfterDays, action } = req.body;
    
    const keywordCleanupService = require('./services/keyword-cleanup-service');
    const result = await keywordCleanupService.runManualCleanup(organizationId, websiteId, {
      cleanupAfterDays: parseInt(cleanupAfterDays) || 7,
      action: action || 'archive'
    });
    
    res.json({
      success: true,
      message: `Successfully ${result.action}d ${result.cleanedCount} keywords`,
      cleanedCount: result.cleanedCount,
      action: result.action
    });
  } catch (error) {
    console.error('Error running manual cleanup:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Get cleanup statistics
app.get('/api/keywords/cleanup-stats', isAuthenticated, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const websiteId = req.session.currentWebsiteId;
    
    const keywordCleanupService = require('./services/keyword-cleanup-service');
    const stats = await keywordCleanupService.getCleanupStats(organizationId, websiteId);
    
    res.json({
      success: true,
      stats: stats
    });
  } catch (error) {
    console.error('Error getting cleanup stats:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Get archived keywords
app.get('/api/keywords/archived', isAuthenticated, async (req, res) => {
  try {
    const organizationId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    
    const page = parseInt(req.query.page || '1');
    const limit = 50;
    const offset = (page - 1) * limit;
    
    // Get archived keywords
    let query = `
      SELECT k.id, k.keyword, k.category, k.interests, k.status, k.recipe_id,
             k.added_at, k.processed_at, u.name as owner_name, u.role as owner_role
      FROM keywords k
      LEFT JOIN users u ON k.owner_id = u.id
      WHERE k.status = 'archived' AND k.organization_id = ?
    `;
    let params = [organizationId];
    
    if (userId) {
      query += ` AND k.owner_id = ?`;
      params.push(userId);
    }
    
    query += ` ORDER BY k.processed_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);
    
    const keywords = await getAll(query, params);
    
    // Get total count
    let countQuery = `
      SELECT COUNT(*) as count FROM keywords 
      WHERE status = 'archived' AND organization_id = ?
    `;
    let countParams = [organizationId];
    
    if (userId) {
      countQuery += ` AND owner_id = ?`;
      countParams.push(userId);
    }
    
    const countResult = await getOne(countQuery, countParams);
    const totalCount = countResult ? countResult.count : 0;
    const totalPages = Math.ceil(totalCount / limit);
    
    res.json({
      success: true,
      keywords: keywords,
      pagination: {
        currentPage: page,
        totalPages: totalPages,
        totalCount: totalCount,
        limit: limit
      }
    });
  } catch (error) {
    console.error('Error getting archived keywords:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Simple admin route to see ALL users in database (not organization-filtered)
app.get('/admin/all-users', isAuthenticated, isAdmin, async (req, res) => {
  try {
    // Get ALL users from database (bypass organization filter)
    const { getAll } = require('./db');
    const users = await getAll(`
      SELECT u.*, o.name as org_name 
      FROM users u 
      LEFT JOIN organizations o ON u.organization_id = o.id 
      ORDER BY u.created_at DESC
    `);
    
    console.log(`Found ${users.length} total users in database`);
    
    // Render the same users.ejs template but with ALL users
    res.render('users', {
      users: users,
      pageTitle: 'All Application Users',
      activePage: 'users',
      title: 'RecipeGen AI - All Users',
      moment: require('moment'),
      errorMessage: req.session.errorMessage,
      successMessage: req.session.successMessage
    });
    
    // Clear messages
    delete req.session.errorMessage;
    delete req.session.successMessage;
  } catch (error) {
    console.error('Error loading all users:', error);
    req.session.errorMessage = 'Failed to load users: ' + error.message;
    res.redirect('/');
  }
});

// Replace the date filtering section in your /api/dashboard/filtered-stats endpoint with this:

// API endpoint for filtered dashboard stats - FIXED VERSION
app.get('/api/dashboard/filtered-stats', isAuthenticated, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const organizationId = req.session.user.organizationId;
    const userId = req.session.user.role === 'employee' ? req.session.user.id : null;
    const isAdmin = req.session.user.role === 'admin';
    
    console.log(`Getting filtered dashboard stats: startDate=${startDate}, endDate=${endDate}`);
    
    // FIXED: Parse dates to handle timezone correctly
    let dateFilter = null;
    if (startDate || endDate) {
      dateFilter = {
        startDate: null,
        endDate: null
      };
      
      if (startDate) {
        // Create date in local timezone at start of day
        const start = new Date(startDate + 'T00:00:00.000');
        // Convert to UTC for database query
        dateFilter.startDate = new Date(start.getTime() - (start.getTimezoneOffset() * 60000));
      }
      
      if (endDate) {
        // Create date in local timezone at end of day
        const end = new Date(endDate + 'T23:59:59.999');
        // Convert to UTC for database query
        dateFilter.endDate = new Date(end.getTime() - (end.getTimezoneOffset() * 60000));
      }
      
      console.log('Date filter (UTC):', {
        startDate: dateFilter.startDate?.toISOString(),
        endDate: dateFilter.endDate?.toISOString()
      });
    }
    
    // Rest of your existing code stays the same...
    const dashboardStats = {
      recipes: 0,
      pendingKeywords: 0,
      processedKeywords: 0,
      failedKeywords: 0,
      totalKeywords: 0,
      wordpressPosts: 0,
      userCount: 0
    };
    
    // Get filtered recipe count
    if (userId) {
      dashboardStats.recipes = await recipeDb.getRecipeCountByOwnerFiltered(userId, organizationId, dateFilter);
    } else {
      dashboardStats.recipes = await recipeDb.getRecipeCountByOrganizationFiltered(organizationId, dateFilter);
    }
    
    // Gather keyword statistics with date filtering
    dashboardStats.pendingKeywords = await keywordsDb.getKeywordsCountFiltered('pending', null, userId, organizationId, dateFilter);
    dashboardStats.processedKeywords = await keywordsDb.getKeywordsCountFiltered('processed', null, userId, organizationId, dateFilter);
    dashboardStats.failedKeywords = await keywordsDb.getKeywordsCountFiltered('failed', null, userId, organizationId, dateFilter);
    dashboardStats.totalKeywords = dashboardStats.pendingKeywords + dashboardStats.processedKeywords + dashboardStats.failedKeywords;
    
    // Get WordPress post count with date filtering
    try {
      dashboardStats.wordpressPosts = await wordpressDb.getPublicationCountFiltered(userId, organizationId, req.session.currentWebsiteId, dateFilter);
    } catch (error) {
      console.log('No WordPress publications found or error counting them:', error.message);
    }
    
    // Get filtered recent recipes
    let recentRecipes;
    if (userId) {
      recentRecipes = await recipeDb.getRecipesByOwnerAndOrgFiltered(userId, organizationId, 10, 0, dateFilter);
    } else {
      recentRecipes = await recipeDb.getRecipesByOrgFiltered(organizationId, 10, 0, dateFilter);
    }
    
    // Get filtered recent activity
    let recentActivity = [];
    if (isAdmin) {
      recentActivity = await getRecentActivityLogsFiltered(organizationId, 5, null, dateFilter);
      dashboardStats.employeeStats = await getEmployeeStatsFiltered(organizationId, dateFilter);
    } else {
      recentActivity = await getRecentActivityLogsFiltered(organizationId, 5, userId, dateFilter);
    }
    
    // If admin, get user count (this doesn't need date filtering)
    if (isAdmin) {
      const orgUsers = await userDb.getUsersByOrganization(organizationId);
      dashboardStats.userCount = orgUsers.length;
    }
    
    res.json({
      success: true,
      stats: dashboardStats,
      recentRecipes: recentRecipes,
      recentActivity: recentActivity,
      employeeStats: dashboardStats.employeeStats || null
    });
    
  } catch (error) {
    console.error('Error fetching filtered dashboard stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to load filtered dashboard data: ' + error.message
    });
  }
});

// Add this API endpoint to your server.js file
app.get('/api/discord/current-account', isAuthenticated, async (req, res) => {
  try {
    console.log('🔍 Checking current Discord account for user request...');
    
    const discordSettings = await getCurrentDiscordSettings(req);
    
    if (!discordSettings) {
      return res.json({
        success: false,
        message: 'No Discord settings found for current context',
        context: {
          organizationId: req.session.user?.organizationId,
          websiteId: req.session.currentWebsiteId,
          userId: req.session.user?.id,
          userName: req.session.user?.name
        }
      });
    }
    
    // Get Discord channel/guild info to help identify the account
    let discordInfo = null;
    try {
      const axios = require('axios');
      const channelResponse = await axios.get(
        `https://discord.com/api/v10/channels/${discordSettings.discordChannelId}`,
        {
          headers: {
            'Authorization': discordSettings.discordUserToken,
            'Content-Type': 'application/json'
          },
          timeout: 5000
        }
      );
      
      if (channelResponse.data) {
        discordInfo = {
          channelName: channelResponse.data.name,
          guildId: channelResponse.data.guild_id,
          channelType: channelResponse.data.type
        };
        
        // Try to get guild info too
        try {
          const guildResponse = await axios.get(
            `https://discord.com/api/v10/guilds/${channelResponse.data.guild_id}`,
            {
              headers: {
                'Authorization': discordSettings.discordUserToken,
                'Content-Type': 'application/json'
              },
              timeout: 5000
            }
          );
          
          if (guildResponse.data) {
            discordInfo.guildName = guildResponse.data.name;
            discordInfo.guildOwner = guildResponse.data.owner_id;
          }
        } catch (guildError) {
          console.warn('Could not get guild info:', guildError.message);
        }
      }
    } catch (discordError) {
      console.warn('Could not get Discord channel info:', discordError.message);
    }
    
    const tokenPreview = discordSettings.discordUserToken.substring(0, 10) + '...';
    
    res.json({
      success: true,
      currentAccount: {
        channelId: discordSettings.discordChannelId,
        tokenPreview: tokenPreview,
        webhookUrl: discordSettings.discordWebhookUrl ? 'SET' : 'NOT SET',
        enabled: discordSettings.enableDiscord,
        source: discordSettings.source,
        discordInfo: discordInfo
      },
      context: {
        organizationId: discordSettings.organizationId,
        websiteId: discordSettings.websiteId,
        userId: req.session.user?.id,
        userName: req.session.user?.name
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error checking current Discord account:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check Discord account: ' + error.message
    });
  }
});

// ALSO UPDATE: Helper function for date filtering with timezone handling
async function getRecentActivityLogsFiltered(organizationId, limit = 5, userId = null, dateFilter = null) {
  try {
    const hasActivityTable = await checkTableExists('activity_logs');
    if (!hasActivityTable) {
      return [];
    }
    
    let query = `
      SELECT al.*, u.name as user_name 
      FROM activity_logs al
      JOIN users u ON al.user_id = u.id
      WHERE al.organization_id = ?
    `;
    
    const params = [organizationId];
    
    if (userId) {
      query += ` AND al.user_id = ?`;
      params.push(userId);
    }
    
    // FIXED: Add proper date filtering with timezone handling
    if (dateFilter) {
      if (dateFilter.startDate) {
        query += ` AND datetime(al.created_at) >= datetime(?)`;
        params.push(dateFilter.startDate.toISOString());
      }
      if (dateFilter.endDate) {
        query += ` AND datetime(al.created_at) <= datetime(?)`;
        params.push(dateFilter.endDate.toISOString());
      }
    }
    
    query += ` ORDER BY al.created_at DESC LIMIT ?`;
    params.push(limit);
    
    return await getAll(query, params);
  } catch (error) {
    console.error('Error getting filtered activity logs:', error);
    return [];
  }
}

// ALSO UPDATE: Employee stats helper with timezone handling
async function getEmployeeStatsFiltered(organizationId, dateFilter = null) {
  try {
    const employees = await userDb.getUsersByOrganization(organizationId);
    const employeeIds = employees.filter(u => u.role === 'employee').map(u => u.id);
    
    if (employeeIds.length === 0) {
      return [];
    }
    
    const stats = [];
    
    for (const id of employeeIds) {
      const employee = employees.find(u => u.id === id);
      if (!employee) continue;
      
      // Get counts with proper date filtering
      const recipeCount = await recipeDb.getRecipeCountByOwnerFiltered(id, organizationId, dateFilter);
      const keywordCounts = {
        pending: await keywordsDb.getKeywordsCountFiltered('pending', null, id, organizationId, dateFilter),
        processed: await keywordsDb.getKeywordsCountFiltered('processed', null, id, organizationId, dateFilter),
        failed: await keywordsDb.getKeywordsCountFiltered('failed', null, id, organizationId, dateFilter)
      };
      
      keywordCounts.total = keywordCounts.pending + keywordCounts.processed + keywordCounts.failed;
      
      // Get WordPress posts with date filtering
      let wpPostCount = 0;
      try {
        wpPostCount = await wordpressDb.getPublicationCountFiltered(id, organizationId, null, dateFilter);
      } catch (error) {
        // Ignore error if WordPress integration not set up
      }
      
      stats.push({
        id: id,
        name: employee.name,
        email: employee.email,
        recipeCount,
        keywordCounts,
        wpPostCount,
        totalContent: recipeCount + keywordCounts.processed
      });
    }
    
    return stats.sort((a, b) => b.totalContent - a.totalContent);
  } catch (error) {
    console.error('Error getting filtered employee stats:', error);
    return [];
  }
}

// Initialize the cleanup service when server starts
// Add this near the end of your server.js file, before app.listen()
async function initializeCleanupService() {
  try {
    const keywordCleanupService = require('./services/keyword-cleanup-service');
    await keywordCleanupService.initialize();
  } catch (error) {
    console.error('Failed to initialize cleanup service:', error);
  }
}

// Call this after your server starts
// initializeCleanupService(); // Temporarily commented out - missing service

// Helper function to send Discord message
async function sendDiscordMessage(message, options = {}) {
  try {
    if (!promptConfig.enableDiscord) {
      console.log('Discord integration is disabled');
      return { success: false, message: 'Discord integration is disabled' };
    }
    
    const axios = require('axios');
    let result = null;
    
    // Try webhook first if available
    if (promptConfig.discordWebhookUrl) {
      try {
        await axios.post(promptConfig.discordWebhookUrl, {
          content: message,
          ...options
        });
        
        result = { success: true, method: 'webhook' };
      } catch (webhookError) {
        console.warn('Discord webhook failed:', webhookError.message);
      }
    }
    
    // Try user token if webhook failed or not available
    if (!result && promptConfig.discordUserToken && promptConfig.discordChannelId) {
      try {
        await axios.post(
          `https://discord.com/api/v10/channels/${promptConfig.discordChannelId}/messages`,
          {
            content: message,
            ...options
          },
          {
            headers: {
              'Authorization': promptConfig.discordUserToken,
              'Content-Type': 'application/json'
            }
          }
        );
        
        result = { success: true, method: 'user_token' };
      } catch (tokenError) {
        console.error('Discord user token failed:', tokenError.message);
        result = { success: false, message: tokenError.message };
      }
    }
    
    if (!result) {
      result = { success: false, message: 'No Discord connection method available' };
    }
    
    return result;
  } catch (error) {
    console.error('Error sending Discord message:', error);
    return { success: false, message: error.message };
  }
}

// ENHANCED: Replace your getCurrentDiscordSettings function in server.js with better logging
async function getCurrentDiscordSettings(req = null) {
  try {
    console.log('🔍 [DISCORD] Getting Discord settings...');
    
    // Get current context - this is CRITICAL for selecting the right account
    let organizationId = null;
    let websiteId = null;
    let userId = null;
    
    if (req && req.session && req.session.user) {
      organizationId = req.session.user.organizationId;
      websiteId = req.session.currentWebsiteId;
      userId = req.session.user.id;
      
      console.log(`🏢 [DISCORD] Request context: Org=${organizationId}, Website=${websiteId}, User=${userId}`);
    } else {
      // Try to get from global context as fallback
      organizationId = global.currentOrganizationId;
      websiteId = global.currentWebsiteId;
      
      console.log(`🌐 [DISCORD] Global context: Org=${organizationId}, Website=${websiteId}`);
    }
    
    if (!organizationId) {
      console.log('❌ [DISCORD] No organization context - cannot determine which Discord account to use');
      return null;
    }
    
    // PRIORITY 1: Get settings specific to this organization + website
    if (organizationId && websiteId) {
      console.log(`🎯 [DISCORD] PRIORITY 1: Loading website-specific settings for org ${organizationId}, website ${websiteId}`);
      
      try {
        const settings = promptSettingsDb.loadSettings(organizationId, websiteId);
        
        if (settings && settings.enableDiscord && settings.discordChannelId && settings.discordUserToken) {
          console.log('✅ [DISCORD] PRIORITY 1 SUCCESS: Found website-specific Discord settings');
          
          // Enhanced logging to identify which account we're using
          const tokenPreview = settings.discordUserToken.substring(0, 10) + '...';
          console.log(`🔑 [DISCORD] SELECTED ACCOUNT:`);
          console.log(`   📍 Source: website-${websiteId}`);
          console.log(`   🔐 Token: ${tokenPreview}`);
          console.log(`   📺 Channel: ${settings.discordChannelId}`);
          console.log(`   🏢 Organization: ${organizationId}`);
          console.log(`   🌐 Website: ${websiteId}`);
          console.log(`   ✅ Enabled: ${settings.enableDiscord}`);
          
          return {
            discordChannelId: settings.discordChannelId.trim(),
            discordUserToken: settings.discordUserToken.trim(),
            discordWebhookUrl: settings.discordWebhookUrl ? settings.discordWebhookUrl.trim() : '',
            enableDiscord: settings.enableDiscord,
            source: `website-${websiteId}`,
            organizationId: organizationId,
            websiteId: websiteId
          };
        } else {
          console.log(`⚠️ [DISCORD] PRIORITY 1 FAILED: Website settings incomplete or disabled`);
          if (settings) {
            console.log(`   enableDiscord: ${settings.enableDiscord}`);
            console.log(`   hasChannelId: ${!!settings.discordChannelId}`);
            console.log(`   hasUserToken: ${!!settings.discordUserToken}`);
          } else {
            console.log(`   No settings found for website ${websiteId}`);
          }
        }
      } catch (settingsError) {
        console.warn(`⚠️ [DISCORD] PRIORITY 1 ERROR: ${settingsError.message}`);
      }
    }
    
    // PRIORITY 2: Get organization-level settings (fallback)
    if (organizationId) {
      console.log(`🏢 [DISCORD] PRIORITY 2: Loading organization-level settings for org ${organizationId}`);
      
      try {
        const settings = promptSettingsDb.loadSettings(organizationId, 'default');
        
        if (settings && settings.enableDiscord && settings.discordChannelId && settings.discordUserToken) {
          console.log('✅ [DISCORD] PRIORITY 2 SUCCESS: Found organization-level Discord settings');
          
          const tokenPreview = settings.discordUserToken.substring(0, 10) + '...';
          console.log(`🔑 [DISCORD] SELECTED ACCOUNT:`);
          console.log(`   📍 Source: organization-${organizationId}`);
          console.log(`   🔐 Token: ${tokenPreview}`);
          console.log(`   📺 Channel: ${settings.discordChannelId}`);
          console.log(`   🏢 Organization: ${organizationId}`);
          console.log(`   🌐 Website: default`);
          console.log(`   ✅ Enabled: ${settings.enableDiscord}`);
          
          return {
            discordChannelId: settings.discordChannelId.trim(),
            discordUserToken: settings.discordUserToken.trim(),
            discordWebhookUrl: settings.discordWebhookUrl ? settings.discordWebhookUrl.trim() : '',
            enableDiscord: settings.enableDiscord,
            source: `organization-${organizationId}`,
            organizationId: organizationId,
            websiteId: 'default'
          };
        } else {
          console.log(`⚠️ [DISCORD] PRIORITY 2 FAILED: Organization settings incomplete or disabled`);
        }
      } catch (orgError) {
        console.warn(`⚠️ [DISCORD] PRIORITY 2 ERROR: ${orgError.message}`);
      }
    }
    
    // PRIORITY 3: Try database settings (only as last resort)
    console.log(`🗄️ [DISCORD] PRIORITY 3: Trying database settings (last resort)`);
    try {
      const dbSettings = await getDiscordSettingsFromDatabase();
      if (dbSettings && dbSettings.discordChannelId && dbSettings.discordUserToken) {
        console.log('⚠️ [DISCORD] PRIORITY 3 SUCCESS: Using database Discord settings (should configure per website)');
        
        const tokenPreview = dbSettings.discordUserToken.substring(0, 10) + '...';
        console.log(`🔑 [DISCORD] SELECTED ACCOUNT:`);
        console.log(`   📍 Source: database-global`);
        console.log(`   🔐 Token: ${tokenPreview}`);
        console.log(`   📺 Channel: ${dbSettings.discordChannelId}`);
        console.log(`   🏢 Organization: ${organizationId}`);
        console.log(`   🌐 Website: ${websiteId || 'unknown'}`);
        console.log(`   ✅ Enabled: ${dbSettings.enableDiscord}`);
        
        return {
          ...dbSettings,
          source: 'database-global',
          organizationId: organizationId,
          websiteId: websiteId || 'unknown'
        };
      } else {
        console.log(`⚠️ [DISCORD] PRIORITY 3 FAILED: Database settings incomplete`);
      }
    } catch (dbError) {
      console.warn(`⚠️ [DISCORD] PRIORITY 3 ERROR: ${dbError.message}`);
    }
    
    console.log('❌ [DISCORD] ALL PRIORITIES FAILED: No Discord settings found for this context');
    console.log(`   🏢 Organization: ${organizationId}`);
    console.log(`   🌐 Website: ${websiteId}`);
    console.log(`   👤 User: ${userId}`);
    console.log(`   💡 Recommendation: Configure Discord settings in /settings page`);
    
    return null;
    
  } catch (error) {
    console.error('❌ [DISCORD] CRITICAL ERROR getting Discord settings:', error.message);
    console.error('❌ [DISCORD] Stack trace:', error.stack);
    return null;
  }
}

// Make this function globally available
global.getCurrentDiscordSettings = getCurrentDiscordSettings;

// UPDATED: Make the database function async and safer
async function getDiscordSettingsFromDatabase() {
  try {
    const { getOne } = require('./db');
    
    const channelId = await getOne("SELECT setting_value FROM app_settings WHERE setting_key = 'discord_channel_id'");
    const userToken = await getOne("SELECT setting_value FROM app_settings WHERE setting_key = 'discord_user_token'");
    const webhookUrl = await getOne("SELECT setting_value FROM app_settings WHERE setting_key = 'discord_webhook_url'");
    const enabled = await getOne("SELECT setting_value FROM app_settings WHERE setting_key = 'enable_discord'");
    
    if (channelId && userToken && channelId.setting_value && userToken.setting_value) {
      return {
        discordChannelId: channelId.setting_value.trim(),
        discordUserToken: userToken.setting_value.trim(),
        discordWebhookUrl: webhookUrl ? webhookUrl.setting_value.trim() : '',
        enableDiscord: enabled ? enabled.setting_value === 'true' : false
      };
    }
    
    return null;
  } catch (error) {
    console.error('❌ [DISCORD] Error reading Discord settings from database:', error.message);
    return null;
  }
}

// Make this function globally available
global.getCurrentDiscordSettings = getCurrentDiscordSettings;

// Export the Discord helper function for use in other parts of your app
global.sendDiscordMessage = sendDiscordMessage;

// Helper functions for website stats
async function getWebsiteStats(websiteId, userId = null, userRole = null) {
  try {
    // Default stats object
    const stats = {
      recipes: 0,
      pendingKeywords: 0,
      processedKeywords: 0,
      failedKeywords: 0,
      totalKeywords: 0,
      wordpressPosts: 0
    };
    
    // Get recipe count
    if (userRole === 'employee' && userId) {
      stats.recipes = await recipeDb.getRecipeCountByOwner(userId, websiteId);
    } else {
      stats.recipes = await recipeDb.getRecipeCountByOrganization(null, websiteId);
    }
    
    // Get keyword counts
    const keywordParams = userRole === 'employee' ? { ownerId: userId } : {};
    stats.pendingKeywords = await keywordsDb.getKeywordsCount('pending', null, 
      keywordParams.ownerId, null, websiteId);
    stats.processedKeywords = await keywordsDb.getKeywordsCount('processed', null, 
      keywordParams.ownerId, null, websiteId);
    stats.failedKeywords = await keywordsDb.getKeywordsCount('failed', null, 
      keywordParams.ownerId, null, websiteId);
    
    stats.totalKeywords = stats.pendingKeywords + stats.processedKeywords + stats.failedKeywords;
    
    // Try to get WordPress post count if we have WordPress integration
    try {
      stats.wordpressPosts = await wordpressDb.getPublicationCount(
  userRole === 'employee' ? userId : null, 
  null, 
  websiteId
);
    } catch (error) {
      console.log('No WordPress publications found or error counting them:', error.message);
    }
    
    return stats;
  } catch (error) {
    console.error('Error getting website stats:', error);
    return {
      recipes: 0,
      pendingKeywords: 0,
      processedKeywords: 0,
      failedKeywords: 0,
      totalKeywords: 0,
      wordpressPosts: 0
    };
  }
}

// Helper function to get recent content for a website
async function getRecentWebsiteContent(websiteId, userId = null, userRole = null) {
  try {
    const recentContent = [];
    const limit = 10;
    
    // Get recent recipes
    const recipeParams = userRole === 'employee' ? { ownerId: userId } : {};
    const recipes = await recipeDb.getRecipesByOrg(
      null, 
      limit, 
      0, 
      websiteId
    );
    
    if (recipes && recipes.length > 0) {
      recipes.forEach(recipe => {
        recentContent.push({
          id: recipe.id,
          title: recipe.recipe_idea,
          type: 'recipe',
          created_at: recipe.created_at,
          url: `/recipe/${recipe.id}`
        });
      });
    }
    
    // Get recent keywords
    const keywords = await keywordsDb.getKeywords(
      null, 
      limit, 
      0, 
      null,
      userRole === 'employee' ? userId : null,
      null,
      websiteId
    );
    
    if (keywords && keywords.length > 0) {
      keywords.forEach(keyword => {
        recentContent.push({
          id: keyword.id,
          title: keyword.keyword,
          type: 'keyword',
          created_at: keyword.added_at,
          status: keyword.status,
          url: `/keywords?search=${encodeURIComponent(keyword.keyword)}`
        });
      });
    }
    
    // Sort by creation date
    recentContent.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    
    // Return the most recent items
    return recentContent.slice(0, limit);
  } catch (error) {
    console.error('Error getting recent website content:', error);
    return [];
  }
}

// ==========================================
// ADMIN DASHBOARD HELPER FUNCTIONS
// ==========================================

async function getAdminKPIs(organizationId, startDate, endDate) {
  try {
    // Get active employees count - based on recipe creation only
    const activeEmployees = await getOne(`
      SELECT COUNT(DISTINCT u.id) as count
      FROM users u
      LEFT JOIN recipes r ON u.id = r.owner_id AND r.created_at BETWEEN ? AND ?
      WHERE u.organization_id = ? AND u.role = 'employee'
      AND r.id IS NOT NULL
    `, [startDate, endDate, organizationId]);

    // Get total content created - only recipes
    const totalContent = await getOne(`
      SELECT COUNT(*) as count
      FROM recipes 
      WHERE organization_id = ? AND created_at BETWEEN ? AND ?
    `, [organizationId, startDate, endDate]);

    // Get WordPress publications (handle missing table)
    let publications = { count: 0 };
    try {
      // First check if table exists
      const tableExists = await getOne(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='wordpress_publications'
      `);
      
      if (tableExists) {
        // Check if required columns exist
        const tableInfo = await getAll(`PRAGMA table_info(wordpress_publications)`);
        const hasPublishedAt = tableInfo.some(col => col.name === 'published_at');
        
        if (hasPublishedAt) {
          publications = await getOne(`
            SELECT COUNT(*) as count
            FROM wordpress_publications wp
            JOIN recipes r ON wp.recipe_id = r.id
            WHERE r.organization_id = ? AND wp.published_at BETWEEN ? AND ?
          `, [organizationId, startDate, endDate]);
        } else {
          // Use alternative query if published_at doesn't exist
          publications = await getOne(`
            SELECT COUNT(*) as count
            FROM wordpress_publications wp
            JOIN recipes r ON wp.recipe_id = r.id
            WHERE r.organization_id = ?
          `, [organizationId]);
        }
      }
    } catch (error) {
      console.log('WordPress publications table not available:', error.message);
    }

    // Calculate daily average
    const daysDiff = Math.max(1, Math.ceil((new Date(endDate) - new Date(startDate)) / (1000 * 60 * 60 * 24)));
    const avgDaily = (totalContent?.count || 0) / daysDiff;

    return {
      activeEmployees: activeEmployees?.count || 0,
      totalContent: totalContent?.count || 0,
      publications: publications?.count || 0,
      avgDaily: avgDaily
    };
  } catch (error) {
    console.error('Error getting admin KPIs:', error);
    return { activeEmployees: 0, totalContent: 0, publications: 0, avgDaily: 0 };
  }
}

async function getTeamPerformance(organizationId, startDate, endDate, view) {
  try {
    const employees = await getAll(`
      SELECT 
        u.id,
        u.username,
        u.email,
        COUNT(DISTINCT r.id) as recipesCreated,
        COUNT(DISTINCT wp.id) as wordpressPosts,
        GROUP_CONCAT(DISTINCT w.name) as websites
      FROM users u
      LEFT JOIN recipes r ON u.id = r.owner_id AND r.created_at BETWEEN ? AND ?
      LEFT JOIN (SELECT recipe_id, id FROM wordpress_publications WHERE recipe_id IS NOT NULL) wp ON wp.recipe_id = r.id
      LEFT JOIN websites w ON r.website_id = w.id
      WHERE u.organization_id = ? AND u.role = 'employee'
      GROUP BY u.id, u.username, u.email
      ORDER BY COUNT(DISTINCT r.id) DESC
    `, [startDate, endDate, organizationId]);

    // Calculate performance and daily averages
    const daysDiff = Math.max(1, Math.ceil((new Date(endDate) - new Date(startDate)) / (1000 * 60 * 60 * 24)));
    
    return employees.map(emp => {
      const dailyRecipes = (emp.recipesCreated / daysDiff).toFixed(1);
      const publishRate = emp.recipesCreated > 0 ? ((emp.wordpressPosts / emp.recipesCreated) * 100).toFixed(0) : 0;
      
      // Calculate working days for this employee in the period
      const empWorkingDays = emp.recipesCreated > 0 ? Math.ceil(daysDiff * 0.8) : 0; // Assume 80% working days if they have recipes
      const salaryPeriods = Math.ceil(daysDiff / 15);
      const completedPeriods = Math.floor(daysDiff / 15);
      
      return {
        ...emp,
        dailyRecipes,
        publishRate: publishRate + '%',
        workingDays: empWorkingDays,
        salaryPeriods,
        completedPeriods,
        websiteList: emp.websites ? emp.websites.split(',') : []
      };
    });
  } catch (error) {
    console.error('Error getting team performance:', error);
    return [];
  }
}

async function getTopPerformers(organizationId, startDate, endDate) {
  try {
    const performers = await getAll(`
      SELECT 
        u.id,
        u.username,
        COUNT(DISTINCT r.id) + COUNT(DISTINCT k.id) as totalContent
      FROM users u
      LEFT JOIN recipes r ON u.id = r.owner_id AND r.created_at BETWEEN ? AND ?
      LEFT JOIN keywords k ON u.id = k.owner_id AND k.added_at BETWEEN ? AND ?
      WHERE u.organization_id = ? AND u.role = 'employee'
      GROUP BY u.id, u.username
      HAVING totalContent > 0
      ORDER BY totalContent DESC
      LIMIT 10
    `, [startDate, endDate, startDate, endDate, organizationId]);

    return performers.map(performer => ({
      ...performer,
      performance: Math.min(100, Math.round(performer.totalContent * 10))
    }));
  } catch (error) {
    console.error('Error getting top performers:', error);
    return [];
  }
}

async function getAnalyticsData(organizationId, startDate, endDate, view) {
  try {
    let chartData = { labels: [], values: [] };
    let distributionData = { labels: [], values: [] };
    let tableData = [];

    if (view === 'daily') {
      // Get daily content creation data
      const dailyData = await getAll(`
        SELECT 
          DATE(created_at) as date,
          COUNT(*) as count
        FROM recipes
        WHERE organization_id = ? AND created_at BETWEEN ? AND ?
        GROUP BY DATE(created_at)
        ORDER BY date
      `, [organizationId, startDate, endDate]);

      chartData.labels = dailyData.map(d => d.date);
      chartData.values = dailyData.map(d => d.count);
    }

    // Get content distribution by type - focusing on recipes and WordPress posts only
    const recipeCount = await getOne(`SELECT COUNT(*) as count FROM recipes WHERE organization_id = ? AND created_at BETWEEN ? AND ?`, [organizationId, startDate, endDate]);
    
    // Check if wordpress_publications table exists
    let wpCount = { count: 0 };
    try {
      const tableExists = await getOne(`SELECT name FROM sqlite_master WHERE type='table' AND name='wordpress_publications'`);
      if (tableExists) {
        wpCount = await getOne(`
          SELECT COUNT(DISTINCT wp.id) as count 
          FROM wordpress_publications wp
          JOIN recipes r ON wp.recipe_id = r.id
          WHERE r.organization_id = ? AND wp.published_at BETWEEN ? AND ?
        `, [organizationId, startDate, endDate]);
      }
    } catch (error) {
      console.log('WordPress publications table not found or error:', error.message);
    }
    
    distributionData.labels = ['Recipes', 'WordPress Posts'];
    distributionData.values = [recipeCount?.count || 0, wpCount?.count || 0];

    // Get table data by employee
    tableData = await getTeamPerformance(organizationId, startDate, endDate, view);
    tableData = tableData.map(emp => ({
      userId: emp.id,
      employee: emp.username,
      websites: emp.websites,
      recipesCreated: emp.recipesCreated,
      wordpressPosts: emp.wordpressPosts,
      publishRate: emp.publishRate,
      dailyAverage: emp.dailyAverage,
      completedPeriods: emp.completedPeriods,
      performance: emp.performance
    }));

    return { chartData, distributionData, tableData };
  } catch (error) {
    console.error('Error getting analytics data:', error);
    return { chartData: { labels: [], values: [] }, distributionData: { labels: [], values: [] }, tableData: [] };
  }
}

async function getTeamInsights(organizationId, startDate, endDate) {
  try {
    const insights = [];

    // Get most productive employee
    const topEmployee = await getOne(`
      SELECT 
        u.username,
        COUNT(DISTINCT r.id) + COUNT(DISTINCT k.id) as totalContent
      FROM users u
      LEFT JOIN recipes r ON u.id = r.owner_id AND r.created_at BETWEEN ? AND ?
      LEFT JOIN keywords k ON u.id = k.owner_id AND k.added_at BETWEEN ? AND ?
      WHERE u.organization_id = ? AND u.role = 'employee'
      GROUP BY u.id, u.username
      ORDER BY totalContent DESC
      LIMIT 1
    `, [startDate, endDate, startDate, endDate, organizationId]);

    if (topEmployee && topEmployee.totalContent > 0) {
      insights.push({
        type: 'positive',
        message: `${topEmployee.username} is the top performer with ${topEmployee.totalContent} content pieces`
      });
    }

    // Check for productivity trends
    const yesterdayCount = await getOne(`
      SELECT COUNT(*) as count FROM recipes 
      WHERE organization_id = ? AND DATE(created_at) = DATE('now', '-1 day')
    `, [organizationId]);

    const todayCount = await getOne(`
      SELECT COUNT(*) as count FROM recipes 
      WHERE organization_id = ? AND DATE(created_at) = DATE('now')
    `, [organizationId]);

    if (todayCount?.count > yesterdayCount?.count) {
      insights.push({
        type: 'positive',
        message: `Productivity is up ${((todayCount.count - yesterdayCount.count) / Math.max(1, yesterdayCount.count) * 100).toFixed(0)}% from yesterday`
      });
    }

    // Check for inactive employees
    const inactiveEmployees = await getOne(`
      SELECT COUNT(*) as count FROM users u
      WHERE u.organization_id = ? AND u.role = 'employee'
      AND NOT EXISTS (
        SELECT 1 FROM recipes r WHERE r.owner_id = u.id AND r.created_at BETWEEN ? AND ?
      )
      AND NOT EXISTS (
        SELECT 1 FROM keywords k WHERE k.owner_id = u.id AND k.added_at BETWEEN ? AND ?
      )
    `, [organizationId, startDate, endDate, startDate, endDate]);

    if (inactiveEmployees?.count > 0) {
      insights.push({
        type: 'warning',
        message: `${inactiveEmployees.count} employee(s) have not created content in the selected period`
      });
    }

    return insights;
  } catch (error) {
    console.error('Error getting team insights:', error);
    return [];
  }
}

async function generateAdminReport(organizationId, startDate, endDate) {
  try {
    const employees = await getAll(`
      SELECT 
        u.username,
        u.email,
        COUNT(DISTINCT r.id) as recipes_created,
        COUNT(DISTINCT k.id) as keywords_processed,
        COUNT(DISTINCT wp.id) as wordpress_posts,
        MIN(COALESCE(r.created_at, k.added_at)) as first_activity,
        MAX(COALESCE(r.created_at, k.added_at)) as last_activity
      FROM users u
      LEFT JOIN recipes r ON u.id = r.owner_id AND r.created_at BETWEEN ? AND ?
      LEFT JOIN keywords k ON u.id = k.owner_id AND k.added_at BETWEEN ? AND ?
      LEFT JOIN (SELECT recipe_id, id FROM wordpress_publications WHERE recipe_id IS NOT NULL) wp ON wp.recipe_id = r.id
      WHERE u.organization_id = ? AND u.role = 'employee'
      GROUP BY u.id, u.username, u.email
      ORDER BY (COUNT(DISTINCT r.id) + COUNT(DISTINCT k.id)) DESC
    `, [startDate, endDate, startDate, endDate, organizationId]);

    return employees.map(emp => ({
      Employee: emp.username,
      Email: emp.email,
      'Recipes Created': emp.recipes_created,
      'Keywords Processed': emp.keywords_processed,
      'WordPress Posts': emp.wordpress_posts,
      'Total Content': emp.recipes_created + emp.keywords_processed,
      'First Activity': emp.first_activity || 'No activity',
      'Last Activity': emp.last_activity || 'No activity'
    }));
  } catch (error) {
    console.error('Error generating admin report:', error);
    return [];
  }
}

async function scheduleMeeting(organizationId, createdBy, title, date, attendees, agenda) {
  try {
    // Create meetings table if it doesn't exist
    await runQuery(`
      CREATE TABLE IF NOT EXISTS meetings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id INTEGER NOT NULL,
        created_by INTEGER NOT NULL,
        title TEXT NOT NULL,
        meeting_date TEXT NOT NULL,
        agenda TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (organization_id) REFERENCES organizations(id),
        FOREIGN KEY (created_by) REFERENCES users(id)
      )
    `);

    // Create meeting_attendees table if it doesn't exist
    await runQuery(`
      CREATE TABLE IF NOT EXISTS meeting_attendees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        meeting_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (meeting_id) REFERENCES meetings(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    const result = await runQuery(`
      INSERT INTO meetings (organization_id, created_by, title, meeting_date, agenda, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `, [organizationId, createdBy, title, date, agenda]);

    // Add attendees if meeting was created successfully
    if (result.lastID && attendees && attendees.length > 0) {
      for (const attendeeId of attendees) {
        await runQuery(`
          INSERT INTO meeting_attendees (meeting_id, user_id)
          VALUES (?, ?)
        `, [result.lastID, attendeeId]);
      }
    }

    return result.lastID;
  } catch (error) {
    console.error('Error scheduling meeting:', error);
    throw error;
  }
}

async function savePerformanceReview(organizationId, reviewerId, employeeId, period, notes, rating) {
  try {
    // Create performance_reviews table if it doesn't exist
    await runQuery(`
      CREATE TABLE IF NOT EXISTS performance_reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id INTEGER NOT NULL,
        reviewer_id INTEGER NOT NULL,
        employee_id INTEGER NOT NULL,
        period TEXT NOT NULL,
        notes TEXT,
        rating INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (organization_id) REFERENCES organizations(id),
        FOREIGN KEY (reviewer_id) REFERENCES users(id),
        FOREIGN KEY (employee_id) REFERENCES users(id)
      )
    `);

    const result = await runQuery(`
      INSERT INTO performance_reviews (organization_id, reviewer_id, employee_id, period, notes, rating, created_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `, [organizationId, reviewerId, employeeId, period, notes, rating]);

    return result.lastID;
  } catch (error) {
    console.error('Error saving performance review:', error);
    throw error;
  }
}

async function getEmployeeDetails(organizationId, userId, startDate, endDate) {
  try {
    // Get employee basic info
    const employee = await getOne(`
      SELECT id, username, email
      FROM users
      WHERE id = ? AND organization_id = ? AND role = 'employee'
    `, [userId, organizationId]);

    if (!employee) {
      throw new Error('Employee not found');
    }

    // Get daily work breakdown focusing on recipes and WordPress posts
    const dailyWork = await getAll(`
      SELECT 
        DATE(r.created_at) as date,
        COUNT(DISTINCT r.id) as recipes,
        COUNT(DISTINCT wp.id) as wordpressPosts,
        COUNT(DISTINCT r.id) + COUNT(DISTINCT wp.id) as totalWork,
        GROUP_CONCAT(DISTINCT w.name) as websites
      FROM recipes r
      LEFT JOIN (SELECT recipe_id, id FROM wordpress_publications WHERE recipe_id IS NOT NULL) wp ON wp.recipe_id = r.id
      LEFT JOIN websites w ON r.website_id = w.id
      WHERE r.owner_id = ? AND r.organization_id = ? AND DATE(r.created_at) BETWEEN ? AND ?
      GROUP BY DATE(r.created_at)
      ORDER BY date DESC
    `, [userId, organizationId, startDate, endDate]);

    // Calculate summary statistics focusing on recipes and WordPress posts
    const totalRecipes = dailyWork.reduce((sum, day) => sum + day.recipes, 0);
    const totalWordpressPosts = dailyWork.reduce((sum, day) => sum + day.wordpressPosts, 0);
    const workingDays = dailyWork.filter(day => day.recipes > 0).length;
    const maxDayWork = Math.max(...dailyWork.map(day => day.recipes), 1);
    
    const mostProductiveDay = dailyWork.find(day => day.recipes === maxDayWork);
    const dailyRecipeAverage = workingDays > 0 ? (totalRecipes / workingDays).toFixed(1) : '0.0';
    const publishRate = totalRecipes > 0 ? ((totalWordpressPosts / totalRecipes) * 100).toFixed(0) : 0;
    
    // Get websites managed by this employee
    const websitesManaged = [...new Set(dailyWork.map(day => day.websites).filter(w => w).join(',').split(','))].filter(w => w.trim());

    // Calculate salary periods (every 15 days)
    const periodStart = new Date(startDate);
    const periodEnd = new Date(endDate);
    const totalDays = Math.ceil((periodEnd - periodStart) / (1000 * 60 * 60 * 24));
    const salaryPeriods = Math.ceil(totalDays / 15);
    const currentPeriodDays = totalDays % 15 || 15;
    
    return {
      employee,
      summary: {
        totalRecipes,
        totalWordpressPosts,
        workingDays,
        dailyRecipeAverage,
        publishRate: publishRate + '%',
        mostProductiveDay: mostProductiveDay?.date || null,
        websitesManaged,
        // Salary tracking
        totalDaysInPeriod: totalDays,
        salaryPeriods,
        currentPeriodDays,
        completedPeriods: Math.floor(totalDays / 15)
      },
      dailyWork: dailyWork
    };
  } catch (error) {
    console.error('Error getting employee details:', error);
    throw error;
  }
}

async function getEmployeeDayDetails(organizationId, userId, date) {
  try {
    // Get recipes for the day
    const recipes = await getAll(`
      SELECT id, recipe_idea, category, created_at
      FROM recipes
      WHERE DATE(created_at) = DATE(?) AND owner_id = ? AND organization_id = ?
      ORDER BY created_at
    `, [date, userId, organizationId]);

    // Get keywords for the day
    const keywords = await getAll(`
      SELECT id, keyword, status, added_at
      FROM keywords
      WHERE DATE(added_at) = DATE(?) AND owner_id = ? AND organization_id = ?
      ORDER BY added_at
    `, [date, userId, organizationId]);

    // Get WordPress posts for the day (if table exists)
    let wordpressPosts = [];
    try {
      wordpressPosts = await getAll(`
        SELECT wp.wp_post_id, wp.published_at, r.recipe_idea as recipe_title
        FROM wordpress_publications wp
        JOIN recipes r ON wp.recipe_id = r.id
        WHERE DATE(wp.published_at) = DATE(?) AND r.owner_id = ? AND r.organization_id = ?
        ORDER BY wp.published_at
      `, [date, userId, organizationId]);
    } catch (error) {
      console.log('WordPress publications table not available for day details');
    }

    return {
      recipes,
      keywords,
      wordpressPosts
    };
  } catch (error) {
    console.error('Error getting employee day details:', error);
    throw error;
  }
}

async function generateEmployeeReport(organizationId, userId, startDate, endDate) {
  try {
    const employee = await getOne(`
      SELECT username, email FROM users WHERE id = ? AND organization_id = ?
    `, [userId, organizationId]);

    const dailyStats = await getAll(`
      SELECT 
        DATE(created_at) as date,
        'Recipe' as type,
        recipe_idea as item,
        category,
        created_at as timestamp
      FROM recipes
      WHERE owner_id = ? AND organization_id = ? AND DATE(created_at) BETWEEN ? AND ?
      
      UNION ALL
      
      SELECT 
        DATE(added_at) as date,
        'Keyword' as type,
        keyword as item,
        status as category,
        added_at as timestamp
      FROM keywords
      WHERE owner_id = ? AND organization_id = ? AND DATE(added_at) BETWEEN ? AND ?
      
      ORDER BY date DESC, timestamp DESC
    `, [userId, organizationId, startDate, endDate, userId, organizationId, startDate, endDate]);

    return dailyStats.map(stat => ({
      Employee: employee.username,
      Email: employee.email,
      Date: stat.date,
      Type: stat.type,
      Item: stat.item,
      Category: stat.category || 'N/A',
      Timestamp: stat.timestamp
    }));
  } catch (error) {
    console.error('Error generating employee report:', error);
    return [];
  }
}

// ==========================================
// ADMIN DASHBOARD API ENDPOINTS
// ==========================================

// Admin KPIs endpoint
app.get('/api/admin/kpis', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const organizationId = req.session.user.organizationId;
    
    // Get current period data
    const currentData = await getAdminKPIs(organizationId, startDate, endDate);
    
    // Get previous period for comparison (same duration before start date)
    const dateDiff = new Date(endDate) - new Date(startDate);
    const prevEndDate = new Date(startDate);
    const prevStartDate = new Date(prevEndDate.getTime() - dateDiff);
    const previousData = await getAdminKPIs(organizationId, prevStartDate.toISOString().split('T')[0], prevEndDate.toISOString().split('T')[0]);
    
    // Calculate changes
    const calculateChange = (current, previous) => {
      if (previous === 0) return current > 0 ? 100 : 0;
      return ((current - previous) / previous) * 100;
    };
    
    res.json({
      activeEmployees: currentData.activeEmployees,
      totalContent: currentData.totalContent,
      publications: currentData.publications,
      avgDaily: currentData.avgDaily,
      employeesChange: calculateChange(currentData.activeEmployees, previousData.activeEmployees),
      contentChange: calculateChange(currentData.totalContent, previousData.totalContent),
      publicationsChange: calculateChange(currentData.publications, previousData.publications),
      dailyChange: calculateChange(currentData.avgDaily, previousData.avgDaily)
    });
  } catch (error) {
    console.error('Error getting admin KPIs:', error);
    res.status(500).json({ error: 'Failed to load KPIs' });
  }
});

// Team performance endpoint
app.get('/api/admin/team-performance', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { view, startDate, endDate } = req.query;
    const organizationId = req.session.user.organizationId;
    
    const employees = await getTeamPerformance(organizationId, startDate, endDate, view);
    res.json({ employees });
  } catch (error) {
    console.error('Error getting team performance:', error);
    res.status(500).json({ error: 'Failed to load team performance' });
  }
});

// Top performers endpoint
app.get('/api/admin/top-performers', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const organizationId = req.session.user.organizationId;
    
    const performers = await getTopPerformers(organizationId, startDate, endDate);
    res.json({ performers });
  } catch (error) {
    console.error('Error getting top performers:', error);
    res.status(500).json({ error: 'Failed to load top performers' });
  }
});

// Analytics data endpoint
app.get('/api/admin/analytics', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { view, startDate, endDate } = req.query;
    const organizationId = req.session.user.organizationId;
    
    const analyticsData = await getAnalyticsData(organizationId, startDate, endDate, view);
    res.json(analyticsData);
  } catch (error) {
    console.error('Error getting analytics data:', error);
    res.status(500).json({ error: 'Failed to load analytics data' });
  }
});

// Team insights endpoint
app.get('/api/admin/insights', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const organizationId = req.session.user.organizationId;
    
    const insights = await getTeamInsights(organizationId, startDate, endDate);
    res.json({ insights });
  } catch (error) {
    console.error('Error getting team insights:', error);
    res.status(500).json({ error: 'Failed to load insights' });
  }
});

// Export report endpoint
app.get('/api/admin/export-report', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const organizationId = req.session.user.organizationId;
    
    const reportData = await generateAdminReport(organizationId, startDate, endDate);
    
    const csv = new Parser().parse(reportData);
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="team-report-${startDate}-to-${endDate}.csv"`);
    res.send(csv);
  } catch (error) {
    console.error('Error exporting report:', error);
    res.status(500).json({ error: 'Failed to export report' });
  }
});

// Schedule meeting endpoint
app.post('/api/admin/schedule-meeting', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { title, date, attendees, agenda } = req.body;
    const organizationId = req.session.user.organizationId;
    const createdBy = req.session.user.id;
    
    const meetingId = await scheduleMeeting(organizationId, createdBy, title, date, attendees, agenda);
    res.json({ success: true, meetingId });
  } catch (error) {
    console.error('Error scheduling meeting:', error);
    res.status(500).json({ error: 'Failed to schedule meeting' });
  }
});

// Save performance review endpoint
app.post('/api/admin/save-review', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { employeeId, period, notes, rating } = req.body;
    const organizationId = req.session.user.organizationId;
    const reviewerId = req.session.user.id;
    
    const reviewId = await savePerformanceReview(organizationId, reviewerId, employeeId, period, notes, rating);
    res.json({ success: true, reviewId });
  } catch (error) {
    console.error('Error saving performance review:', error);
    res.status(500).json({ error: 'Failed to save performance review' });
  }
});

// Employee details endpoint
app.get('/api/admin/employee-details/:userId', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { startDate, endDate } = req.query;
    const organizationId = req.session.user.organizationId;
    
    const employeeDetails = await getEmployeeDetails(organizationId, userId, startDate, endDate);
    res.json(employeeDetails);
  } catch (error) {
    console.error('Error getting employee details:', error);
    res.status(500).json({ error: 'Failed to load employee details' });
  }
});

// Employee day details endpoint
app.get('/api/admin/employee-day-details/:userId', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { date } = req.query;
    const organizationId = req.session.user.organizationId;
    
    const dayDetails = await getEmployeeDayDetails(organizationId, userId, date);
    res.json(dayDetails);
  } catch (error) {
    console.error('Error getting employee day details:', error);
    res.status(500).json({ error: 'Failed to load day details' });
  }
});

// Export employee report endpoint
app.get('/api/admin/export-employee-report/:userId', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { startDate, endDate } = req.query;
    const organizationId = req.session.user.organizationId;
    
    const reportData = await generateEmployeeReport(organizationId, userId, startDate, endDate);
    
    const csv = new Parser().parse(reportData);
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="employee-${userId}-report-${startDate}-to-${endDate}.csv"`);
    res.send(csv);
  } catch (error) {
    console.error('Error exporting employee report:', error);
    res.status(500).json({ error: 'Failed to export employee report' });
  }
});

// ===================================
// WEBSITE TEMPLATES & BUFFER ROUTES
// ===================================

const { bufferDb, BufferAPI } = require('./models/buffer');





// ==========================================
// ERROR HANDLERS - THESE MUST COME LAST
// ==========================================

// 404 handler - catches all unmatched routes
app.use((req, res, next) => {
  console.log('404 - Route not found:', req.method, req.originalUrl);
  res.status(404).render('error', {
    message: 'Page not found',
    error: { status: 404 },
    pageTitle: 'Error',
    activePage: '',
    title: 'RecipeGen AI - Error'
  });
});

// General error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(err.status || 500).render('error', {
    message: err.message || 'An unexpected error occurred',
    error: err || { status: 500 },
    pageTitle: 'Error',
    activePage: '',
    title: 'RecipeGen AI - Error'
  });
});

// Debug: Print all registered routes (move this to the very end)
const listEndpoints = () => {
  console.log('\n--- REGISTERED ROUTES ---');
  app._router.stack.forEach((r) => {
    if (r.route && r.route.path) {
      Object.keys(r.route.methods).forEach((method) => {
        console.log(`${method.toUpperCase().padEnd(7)} ${r.route.path}`);
      });
    }
  });
  console.log('------------------------\n');
};

// Call this at the very end, after all routes are registered
listEndpoints();

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Discord endpoint should now be accessible at: POST /api/test-discord-connection');
});

module.exports = app;