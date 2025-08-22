// Database utility module for interacting with the SQLite database
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { v4: uuidv4 } = require('uuid');

// Create a connection to the database
const db = new sqlite3.Database(path.join(__dirname, 'data', 'recipes.db'));

// Add at the beginning of db.js
const originalRunQuery = runQuery;
runQuery = function(query, params = []) {
    // Log any INSERT operations
    if (query.toLowerCase().includes('insert into')) {
        console.log('DATABASE INSERT OPERATION:');
        console.log('Query:', query);
        console.log('Params:', params);
    }
    return originalRunQuery(query, params);
};

// Enable foreign key constraints
db.run('PRAGMA foreign_keys = ON;', (err) => {
  if (err) {
    console.error('Error enabling foreign key constraints:', err.message);
  } else {
    console.log('Foreign key constraints enabled');
  }
});

// Helper function to add website filter to queries
function addWebsiteFilter(query, params = [], tableAlias = '') {
  // Skip if no global website context
  if (!global.currentWebsiteId) {
    return { query, params };
  }
  
  const prefix = tableAlias ? `${tableAlias}.` : '';
  
  // Check if query already has a WHERE clause
  if (query.toLowerCase().includes('where')) {
    // Add to existing WHERE clause
    query += ` AND ${prefix}website_id = ?`;
  } else {
    // Add new WHERE clause
    query += ` WHERE ${prefix}website_id = ?`;
  }
  
  // Add website_id parameter
  params.push(global.currentWebsiteId);
  
  return { query, params };
}

// Helper to run queries as promises
function runQuery(query, params = []) {
    return new Promise((resolve, reject) => {
        db.run(query, params, function(err) {
            if (err) {
                reject(err);
            } else {
                resolve({ lastID: this.lastID, changes: this.changes, id: params[0] });
            }
        });
    });
}

// Helper to get a single row
function getOne(query, params = []) {
    return new Promise((resolve, reject) => {
        db.get(query, params, (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row);
            }
        });
    });
}

// Helper to get multiple rows
function getAll(query, params = []) {
    return new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
}

// Recipe operations
const recipeDb = {
    // Create a new recipe entry with ownership
    async createRecipe(recipeData) {
        const id = uuidv4();
        const { recipeIdea, category, interests, language, ownerId, organizationId, websiteId } = recipeData;
        
        // Use explicit websiteId or fallback to global context
        const effectiveWebsiteId = websiteId || global.currentWebsiteId;
        
        await runQuery(
            `INSERT INTO recipes (id, recipe_idea, category, interests, language, owner_id, organization_id, website_id) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, recipeIdea, category, interests, language, ownerId, organizationId, effectiveWebsiteId]
        );
        
        return id;
    },

    // Add to recipeDb in db.js
    async getRecipeCountByOwner(ownerId, websiteId = null) {
        let query = `SELECT COUNT(*) as count
                     FROM recipes 
                     WHERE owner_id = ?`;
        let params = [ownerId];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        const result = await getOne(query, params);
        return result ? result.count : 0;
    },

    async getRecipeCountByOrganization(organizationId, websiteId = null) {
        let query = `SELECT COUNT(*) as count
                     FROM recipes 
                     WHERE organization_id = ?`;
        let params = [organizationId];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        const result = await getOne(query, params);
        return result ? result.count : 0;
    },
    
    /**
     * Create multiple recipes in batch with ownership
     * @param {Array} recipesData - Array of recipe data objects
     * @returns {Promise<Array>} - Array of created recipe IDs
     */
    async createRecipesBatch(recipesData) {
        if (!Array.isArray(recipesData) || recipesData.length === 0) {
            throw new Error('No recipe data provided');
        }
        
        const recipeIds = [];
        
        // Use a transaction for better performance and atomicity
        await new Promise((resolve, reject) => {
            db.run('BEGIN TRANSACTION', async (err) => {
                if (err) {
                    return reject(err);
                }
                
                try {
                    for (const recipeData of recipesData) {
                        const id = uuidv4();
                        const { recipeIdea, category, interests, language, ownerId, organizationId, websiteId } = recipeData;
                        
                        // Use explicit websiteId or fallback to global context
                        const effectiveWebsiteId = websiteId || global.currentWebsiteId;
                        
                        await runQuery(
                            `INSERT INTO recipes (id, recipe_idea, category, interests, language, owner_id, organization_id, website_id) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                            [id, recipeIdea, category, interests, language, ownerId, organizationId, effectiveWebsiteId]
                        );
                        
                        recipeIds.push(id);
                    }
                    
                    db.run('COMMIT', (err) => {
                        if (err) {
                            return reject(err);
                        }
                        resolve();
                    });
                } catch (e) {
                    db.run('ROLLBACK', () => {
                        reject(e);
                    });
                }
            });
        });
        
        return recipeIds;
    },
    
    // Get all recipes
    async getAllRecipes(limit = 50, offset = 0, websiteId = null) {
        let query = `SELECT id, recipe_idea, category, interests, language, owner_id, organization_id, website_id, created_at
                     FROM recipes`;
        let params = [];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` WHERE website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` WHERE website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        
        return await getAll(query, params);
    },
    
    // Get recipes based on user role and permissions
    // Make sure ALL content access functions follow this pattern
    async getRecipesByUser(req, limit = 50, offset = 0) {
        // Get organization ID from the session
        const organizationId = req.session.user.organizationId;
        
        let query;
        let params;
        
        // Critical condition - ensure ALL data queries do this role check!
        if (req.session.user.role === 'employee') {
            query = `
                SELECT id, recipe_idea, category, interests, language, owner_id, organization_id, website_id, created_at 
                FROM recipes 
                WHERE organization_id = ? AND owner_id = ?`;
            params = [organizationId, req.session.user.id];
            
            // Add website filter
            if (global.currentWebsiteId) {
                query += ` AND website_id = ?`;
                params.push(global.currentWebsiteId);
            }
            
            query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
            params.push(limit, offset);
        } else {
            // Admins see organization-wide data
            query = `
                SELECT id, recipe_idea, category, interests, language, owner_id, organization_id, website_id, created_at 
                FROM recipes 
                WHERE organization_id = ?`;
            params = [organizationId];
            
            // Add website filter
            if (global.currentWebsiteId) {
                query += ` AND website_id = ?`;
                params.push(global.currentWebsiteId);
            }
            
            query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
            params.push(limit, offset);
        }
        
        return await getAll(query, params);
    },
    
    // Search recipes
    async searchRecipes(searchTerm, limit = 50, offset = 0, websiteId = null) {
        const searchPattern = `%${searchTerm}%`;
        let query = `SELECT id, recipe_idea, category, interests, language, owner_id, organization_id, website_id, created_at
                     FROM recipes 
                     WHERE (recipe_idea LIKE ? OR category LIKE ? OR interests LIKE ?)`;
        let params = [searchPattern, searchPattern, searchPattern];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        
        return await getAll(query, params);
    },
    
    // Search recipes with user permissions
    async searchRecipesByUser(req, searchTerm, limit = 50, offset = 0) {
        const organizationId = req.session.user.organizationId;
        const searchPattern = `%${searchTerm}%`;
        
        let query;
        let params;
        
        if (req.session.user.role === 'employee') {
            query = `
                SELECT id, recipe_idea, category, interests, language, owner_id, organization_id, website_id, created_at
                FROM recipes 
                WHERE organization_id = ? AND owner_id = ? 
                AND (recipe_idea LIKE ? OR category LIKE ? OR interests LIKE ?)`;
            params = [organizationId, req.session.user.id, searchPattern, searchPattern, searchPattern];
            
            // Add website filter
            if (global.currentWebsiteId) {
                query += ` AND website_id = ?`;
                params.push(global.currentWebsiteId);
            }
            
            query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
            params.push(limit, offset);
        } else {
            query = `
                SELECT id, recipe_idea, category, interests, language, owner_id, organization_id, website_id, created_at
                FROM recipes 
                WHERE organization_id = ? 
                AND (recipe_idea LIKE ? OR category LIKE ? OR interests LIKE ?)`;
            params = [organizationId, searchPattern, searchPattern, searchPattern];
            
            // Add website filter
            if (global.currentWebsiteId) {
                query += ` AND website_id = ?`;
                params.push(global.currentWebsiteId);
            }
            
            query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
            params.push(limit, offset);
        }
        
        return await getAll(query, params);
    },
    
    // Get recipes for a specific user
    async getRecipesByOwner(ownerId, limit = 50, offset = 0, websiteId = null) {
        let query = `SELECT id, recipe_idea, category, interests, language, website_id, created_at
                     FROM recipes 
                     WHERE owner_id = ?`;
        let params = [ownerId];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        
        return await getAll(query, params);
    },
    
    // Get recipes for a specific organization
    async getRecipesByOrganization(organizationId, limit = 50, offset = 0, userId = null, websiteId = null) {
        let query = `SELECT id, recipe_idea, category, interests, language, website_id, created_at
                    FROM recipes 
                    WHERE organization_id = ?`;
        let params = [organizationId];
        
        // If userId is provided, add owner filter for employees
        if (userId) {
            query += ` AND owner_id = ?`;
            params.push(userId);
        }
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        // Add ordering and pagination
        query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        
        return await getAll(query, params);
    },
    
    // Get recipes for a specific organization with owner_id in results
    async getRecipesByOrg(organizationId, limit = 50, offset = 0, websiteId = null) {
        console.log(`Getting recipes for organization: ${organizationId}`);
        
        let query = `SELECT r.id, r.recipe_idea, r.category, r.interests, r.language, 
                            r.owner_id, r.organization_id, r.website_id, r.created_at,
                            u.name as owner_name, u.role as owner_role
                     FROM recipes r
                     LEFT JOIN users u ON r.owner_id = u.id
                     WHERE r.organization_id = ?`;
        let params = [organizationId];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND r.website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND r.website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        query += ` ORDER BY r.created_at DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        
        return await getAll(query, params);
    },

    // Similarly, update the getRecipeById function:
    async getRecipeById(id, websiteId = null) {
        let query = `SELECT r.id, r.recipe_idea, r.category, r.interests, r.language, 
                            r.owner_id, r.organization_id, r.website_id, r.created_at, r.last_updated,
                            u.name as owner_name, u.role as owner_role
                     FROM recipes r
                     LEFT JOIN users u ON r.owner_id = u.id
                     WHERE r.id = ?`;
        let params = [id];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND r.website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND r.website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        return await getOne(query, params);
    },
    
    // Get recipes for a specific owner within an organization
    async getRecipesByOwnerAndOrg(ownerId, organizationId, limit = 50, offset = 0, websiteId = null) {
        console.log(`Getting recipes for owner ${ownerId} in organization ${organizationId}`);
        
        let query = `SELECT id, recipe_idea, category, interests, language, owner_id, organization_id, website_id, created_at
                     FROM recipes 
                     WHERE owner_id = ? AND organization_id = ?`;
        let params = [ownerId, organizationId];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        
        return await getAll(query, params);
    },
    
    // Search recipes by owner
    async searchRecipesByOwner(ownerId, searchTerm, limit = 50, offset = 0, websiteId = null) {
        const searchPattern = `%${searchTerm}%`;
        
        let query = `SELECT id, recipe_idea, category, interests, language, owner_id, organization_id, website_id, created_at
                     FROM recipes 
                     WHERE owner_id = ? AND (recipe_idea LIKE ? OR category LIKE ? OR interests LIKE ?)`;
        let params = [ownerId, searchPattern, searchPattern, searchPattern];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        
        return await getAll(query, params);
    },
    
    // Search recipes by organization
    async searchRecipesInOrganization(organizationId, searchTerm, limit = 50, offset = 0, websiteId = null) {
        const searchPattern = `%${searchTerm}%`;
        
        let query = `SELECT id, recipe_idea, category, interests, language, owner_id, organization_id, website_id, created_at
                     FROM recipes 
                     WHERE organization_id = ? AND (recipe_idea LIKE ? OR category LIKE ? OR interests LIKE ?)`;
        let params = [organizationId, searchPattern, searchPattern, searchPattern];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        
        return await getAll(query, params);
    },
    
    // Get recent recipes
    async getRecentRecipes(limit = 10, websiteId = null) {
        let query = `SELECT id, recipe_idea, category, interests, language, owner_id, organization_id, website_id, created_at
                     FROM recipes`;
        let params = [];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` WHERE website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` WHERE website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        query += ` ORDER BY created_at DESC LIMIT ?`;
        params.push(limit);
        
        return await getAll(query, params);
    },
    
    /**
     * Delete a recipe and all its associated content
     * @param {string} recipeId - The ID of the recipe to delete
     * @returns {Promise<boolean>} - True if successful, false otherwise
     */
    async deleteRecipe(recipeId, websiteId = null) {
        console.log(`Starting deletion process for recipe ID: ${recipeId}`);
        
        return new Promise((resolve, reject) => {
            // Begin a transaction
            db.run('PRAGMA foreign_keys = ON;', (err) => {
                if (err) {
                    console.error('Error enabling foreign keys:', err);
                    return reject(err);
                }
                
                db.run('BEGIN TRANSACTION', (err) => {
                    if (err) {
                        console.error('Error starting transaction:', err);
                        return reject(err);
                    }

                    console.log('Transaction started, attempting to delete recipe');
                    
                    // Try to delete the recipe directly and let CASCADE handle the rest
                    // Add website filter if applicable
                    let query = 'DELETE FROM recipes WHERE id = ?';
                    let params = [recipeId];
                    
                    // If websiteId is provided explicitly, use it
                    if (websiteId) {
                        query += ` AND website_id = ?`;
                        params.push(websiteId);
                    } 
                    // Otherwise use the global context
                    else if (global.currentWebsiteId) {
                        query += ` AND website_id = ?`;
                        params.push(global.currentWebsiteId);
                    }
                    
                    db.run(query, params, function(err) {
                        if (err) {
                            console.error('Error deleting recipe:', err);
                            db.run('ROLLBACK', () => {
                                reject(err);
                            });
                            return;
                        }
                        
                        console.log(`Rows affected: ${this.changes}`);
                        
                        if (this.changes === 0) {
                            console.warn('No rows deleted - recipe may not exist');
                        }
                        
                        // Commit the transaction
                        db.run('COMMIT', (err) => {
                            if (err) {
                                console.error('Error committing transaction:', err);
                                db.run('ROLLBACK', () => {
                                    reject(err);
                                });
                                return;
                            }

                            console.log('Recipe successfully deleted with cascading deletes');
                            resolve(true);
                        });
                    });
                });
            });
        });
    },

    // NEW FILTERED FUNCTIONS FROM SECOND FILE

    async getRecipeCountByOwnerFiltered(ownerId, organizationId, dateFilter = null, websiteId = null) {
    let query = `SELECT COUNT(*) as count
                 FROM recipes 
                 WHERE owner_id = ? AND organization_id = ?`;
    let params = [ownerId, organizationId];
    
    // FIXED: Add proper date filtering with datetime comparison
    if (dateFilter) {
        if (dateFilter.startDate) {
            query += ` AND datetime(created_at) >= datetime(?)`;
            params.push(dateFilter.startDate.toISOString());
        }
        if (dateFilter.endDate) {
            query += ` AND datetime(created_at) <= datetime(?)`;
            params.push(dateFilter.endDate.toISOString());
        }
    }
    
    // Add website filter
    if (websiteId) {
        query += ` AND website_id = ?`;
        params.push(websiteId);
    } else if (global.currentWebsiteId) {
        query += ` AND website_id = ?`;
        params.push(global.currentWebsiteId);
    }
    
    console.log('Recipe count query:', query);
    console.log('Recipe count params:', params);
    
    const result = await getOne(query, params);
    return result ? result.count : 0;
},

    // Get recipe count by organization with date filtering
    async getRecipeCountByOrganizationFiltered(organizationId, dateFilter = null, websiteId = null) {
    let query = `SELECT COUNT(*) as count
                 FROM recipes 
                 WHERE organization_id = ?`;
    let params = [organizationId];
    
    // FIXED: Add proper date filtering with datetime comparison
    if (dateFilter) {
        if (dateFilter.startDate) {
            query += ` AND datetime(created_at) >= datetime(?)`;
            params.push(dateFilter.startDate.toISOString());
        }
        if (dateFilter.endDate) {
            query += ` AND datetime(created_at) <= datetime(?)`;
            params.push(dateFilter.endDate.toISOString());
        }
    }
    
    // Add website filter
    if (websiteId) {
        query += ` AND website_id = ?`;
        params.push(websiteId);
    } else if (global.currentWebsiteId) {
        query += ` AND website_id = ?`;
        params.push(global.currentWebsiteId);
    }
    
    console.log('Organization recipe count query:', query);
    console.log('Organization recipe count params:', params);
    
    const result = await getOne(query, params);
    return result ? result.count : 0;
},

    // Get recipes by owner and organization with date filtering
   async getRecipesByOwnerAndOrgFiltered(ownerId, organizationId, limit = 50, offset = 0, dateFilter = null, websiteId = null) {
    console.log(`Getting filtered recipes for owner ${ownerId} in organization ${organizationId}`);
    
    let query = `SELECT r.id, r.recipe_idea, r.category, r.interests, r.language, 
                        r.owner_id, r.organization_id, r.website_id, r.created_at,
                        u.name as owner_name, u.role as owner_role
                 FROM recipes r
                 LEFT JOIN users u ON r.owner_id = u.id
                 WHERE r.owner_id = ? AND r.organization_id = ?`;
    let params = [ownerId, organizationId];
    
    // FIXED: Add proper date filtering with datetime comparison
    if (dateFilter) {
        if (dateFilter.startDate) {
            query += ` AND datetime(r.created_at) >= datetime(?)`;
            params.push(dateFilter.startDate.toISOString());
        }
        if (dateFilter.endDate) {
            query += ` AND datetime(r.created_at) <= datetime(?)`;
            params.push(dateFilter.endDate.toISOString());
        }
    }
    
    // Add website filter
    if (websiteId) {
        query += ` AND r.website_id = ?`;
        params.push(websiteId);
    } else if (global.currentWebsiteId) {
        query += ` AND r.website_id = ?`;
        params.push(global.currentWebsiteId);
    }
    
    query += ` ORDER BY r.created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);
    
    console.log('Filtered recipes query:', query);
    console.log('Filtered recipes params:', params);
    
    return await getAll(query, params);
},
    // Get recipes by organization with date filtering
    async getRecipesByOrgFiltered(organizationId, limit = 50, offset = 0, dateFilter = null, websiteId = null) {
    console.log(`Getting filtered recipes for organization: ${organizationId}`);
    
    let query = `SELECT r.id, r.recipe_idea, r.category, r.interests, r.language, 
                        r.owner_id, r.organization_id, r.website_id, r.created_at,
                        u.name as owner_name, u.role as owner_role
                 FROM recipes r
                 LEFT JOIN users u ON r.owner_id = u.id
                 WHERE r.organization_id = ?`;
    let params = [organizationId];
    
    // FIXED: Add proper date filtering with datetime comparison
    if (dateFilter) {
        if (dateFilter.startDate) {
            query += ` AND datetime(r.created_at) >= datetime(?)`;
            params.push(dateFilter.startDate.toISOString());
        }
        if (dateFilter.endDate) {
            query += ` AND datetime(r.created_at) <= datetime(?)`;
            params.push(dateFilter.endDate.toISOString());
        }
    }
    
    // Add website filter
    if (websiteId) {
        query += ` AND r.website_id = ?`;
        params.push(websiteId);
    } else if (global.currentWebsiteId) {
        query += ` AND r.website_id = ?`;
        params.push(global.currentWebsiteId);
    }
    
    query += ` ORDER BY r.created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);
    
    console.log('Filtered org recipes query:', query);
    console.log('Filtered org recipes params:', params);
    
    return await getAll(query, params);
},
};

// Facebook content operations
const facebookDb = {
    // Save Facebook content
    async saveFacebookContent(recipeId, facebookData) {
        const id = uuidv4();
        const { recipe, title, fbCaption, mjPrompt, allIngredients, websiteId } = facebookData;
        
        // Use explicit websiteId or fallback to global context
        const effectiveWebsiteId = websiteId || global.currentWebsiteId;
        
        await runQuery(
            `INSERT INTO facebook_content (id, recipe_id, recipe_text, title, ingredients, fb_caption, mj_prompt, website_id) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, recipeId, recipe, title, allIngredients, fbCaption, mjPrompt, effectiveWebsiteId]
        );
        
        return id;
    },
    
    // Get Facebook content for a recipe
    async getFacebookContentByRecipeId(recipeId, organizationId = null, userId = null, websiteId = null) {
        // If organization filtering is requested
        if (organizationId) {
            // First get the recipe to check ownership
            const recipe = await recipeDb.getRecipeById(recipeId);
            
            // Filter by organization
            if (!recipe || recipe.organization_id !== organizationId) {
                return null;
            }
            
            // Then filter by owner if userId is provided (for employees)
            if (userId && recipe.owner_id !== userId) {
                return null;
            }
        }
        
        // Query with website filter
        let query = `SELECT * FROM facebook_content WHERE recipe_id = ?`;
        let params = [recipeId];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        // Return the facebook content
        return await getOne(query, params);
    }
};

// Pinterest variation operations
const pinterestDb = {
    // Save a Pinterest variation
    async savePinterestVariation(recipeId, variationData, variationNumber) {
        const id = uuidv4();
        const { pinTitle, pinDesc, overlay, metaTitle, metaDesc, metaSlug, websiteId } = variationData;
        
        // Use explicit websiteId or fallback to global context
        const effectiveWebsiteId = websiteId || global.currentWebsiteId;
        
        await runQuery(
            `INSERT INTO pinterest_variations 
             (id, recipe_id, variation_number, pin_title, pin_description, overlay_text, meta_title, meta_description, meta_slug, website_id) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, recipeId, variationNumber, pinTitle, pinDesc, overlay, metaTitle, metaDesc, metaSlug, effectiveWebsiteId]
        );
        
        return id;
    },
    
    // Get all Pinterest variations for a recipe
    async getVariationsByRecipeId(recipeId, websiteId = null) {
        let query = `SELECT * FROM pinterest_variations 
                     WHERE recipe_id = ?`;
        let params = [recipeId];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        query += ` ORDER BY variation_number ASC`;
        
        return await getAll(query, params);
    },
    
    // Get a specific Pinterest variation
    async getVariationById(id, websiteId = null) {
        let query = `SELECT * FROM pinterest_variations WHERE id = ?`;
        let params = [id];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        return await getOne(query, params);
    }
};

// Blog content operations
const blogDb = {
    // Save blog content
    async saveBlogContent(recipeId, htmlContent, pinterestVariationId = null, websiteId = null) {
        const id = uuidv4();
        
        // Use explicit websiteId or fallback to global context
        const effectiveWebsiteId = websiteId || global.currentWebsiteId;
        
        await runQuery(
            `INSERT INTO blog_content (id, recipe_id, pinterest_variation_id, html_content, website_id) 
             VALUES (?, ?, ?, ?, ?)`,
            [id, recipeId, pinterestVariationId, htmlContent, effectiveWebsiteId]
        );
        
        return id;
    },
    
    // Get blog content for a recipe
    async getBlogContentByRecipeId(recipeId, websiteId = null) {
        let query = `SELECT * FROM blog_content WHERE recipe_id = ?`;
        let params = [recipeId];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        query += ` ORDER BY created_at DESC LIMIT 1`;
        
        return await getOne(query, params);
    },
    
    // Update blog content for a recipe (when regenerating with a different variation)
    async updateBlogContent(recipeId, htmlContent, pinterestVariationId = null, websiteId = null) {
        // Use explicit websiteId or fallback to global context
        const effectiveWebsiteId = websiteId || global.currentWebsiteId;
        
        // Build the query for checking if blog content exists with website filter
        let checkQuery = `SELECT id FROM blog_content WHERE recipe_id = ?`;
        let checkParams = [recipeId];
        
        if (effectiveWebsiteId) {
            checkQuery += ` AND website_id = ?`;
            checkParams.push(effectiveWebsiteId);
        }
        
        // Check if blog content already exists with website filter
        const existing = await getOne(checkQuery, checkParams);
        
        if (existing) {
            // Update instead of insert
            let updateQuery = `UPDATE blog_content 
                               SET html_content = ?, pinterest_variation_id = ?, created_at = CURRENT_TIMESTAMP 
                               WHERE recipe_id = ?`;
            let updateParams = [htmlContent, pinterestVariationId, recipeId];
            
            if (effectiveWebsiteId) {
                updateQuery += ` AND website_id = ?`;
                updateParams.push(effectiveWebsiteId);
            }
            
            await runQuery(updateQuery, updateParams);
            return existing.id;
        } else {
            // Insert new record
            return await blogDb.saveBlogContent(recipeId, htmlContent, pinterestVariationId, effectiveWebsiteId);
        }
    }
};

// Keywords operations with ownership
const keywordsDb = {
    // Add a new keyword with ownership
    async addKeyword(keywordData) {
        const id = uuidv4();
        const { keyword, category, interests, ownerId, organizationId, websiteId } = keywordData;
        
        // Use explicit websiteId or fallback to global context
        const effectiveWebsiteId = websiteId || global.currentWebsiteId;
        
        await runQuery(
            `INSERT INTO keywords (id, keyword, category, interests, status, owner_id, organization_id, website_id) 
             VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)`,
            [id, keyword, category, interests, ownerId, organizationId, effectiveWebsiteId]
        );
        
        return id;
    },
    
async addKeywordsBatch(keywordsData) {
    if (!Array.isArray(keywordsData) || keywordsData.length === 0) {
        throw new Error('No keywords provided');
    }
    
    console.log(`Adding batch of ${keywordsData.length} keywords`);
    
    // Validate that each keyword has the required owner and organization
    const invalidKeywords = keywordsData.filter(k => !k.ownerId || !k.organizationId);
    if (invalidKeywords.length > 0) {
        console.error('Found keywords missing owner or organization:', invalidKeywords);
        throw new Error('All keywords must have an owner and organization');
    }
    
    const keywordIds = [];
    
    // Use a transaction for better performance and atomicity
    await new Promise((resolve, reject) => {
        db.run('BEGIN TRANSACTION', async (err) => {
            if (err) {
                return reject(err);
            }
            
            try {
                for (const keywordData of keywordsData) {
                    const id = uuidv4();
                    const { keyword, category, interests, image_url, full_recipe, ownerId, organizationId, websiteId } = keywordData;
                    
                    // Use explicit websiteId or fallback to global context
                    const effectiveWebsiteId = websiteId || global.currentWebsiteId;
                    
                    console.log(`Inserting keyword: "${keyword}" for owner: ${ownerId}, org: ${organizationId}`);
                    
                    await runQuery(
                        `INSERT INTO keywords (id, keyword, category, interests, image_url, full_recipe, status, owner_id, organization_id, website_id, added_at) 
                         VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, CURRENT_TIMESTAMP)`,
                        [id, keyword, category, interests, image_url, full_recipe, ownerId, organizationId, effectiveWebsiteId]
                    );
                    
                    keywordIds.push(id);
                }
                
                db.run('COMMIT', (err) => {
                    if (err) {
                        return reject(err);
                    }
                    resolve();
                });
            } catch (e) {
                console.error('Error in transaction, rolling back:', e);
                db.run('ROLLBACK', () => {
                    reject(e);
                });
            }
        });
    });
    
    return keywordIds;
},
    
    async getKeywords(status = null, limit = 100, offset = 0, searchTerm = null, ownerId = null, organizationId = null, websiteId = null) {
    let query = `SELECT id, keyword, category, interests, image_url, full_recipe, status, recipe_id, owner_id, organization_id, website_id, added_at, processed_at
FROM keywords `;
    
    const params = [];
    let whereAdded = false;
        
        // Add status filter if provided
        if (status) {
            query += ` WHERE status = ?`;
            params.push(status);
            whereAdded = true;
        }
        
        // Add owner filter if provided
        if (ownerId) {
            if (whereAdded) {
                query += ` AND owner_id = ?`;
            } else {
                query += ` WHERE owner_id = ?`;
                whereAdded = true;
            }
            params.push(ownerId);
        }
        
        // Add organization filter if provided
        if (organizationId) {
            if (whereAdded) {
                query += ` AND organization_id = ?`;
            } else {
                query += ` WHERE organization_id = ?`;
                whereAdded = true;
            }
            params.push(organizationId);
        }
        
        // Add website filter
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            if (whereAdded) {
                query += ` AND website_id = ?`;
            } else {
                query += ` WHERE website_id = ?`;
                whereAdded = true;
            }
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            if (whereAdded) {
                query += ` AND website_id = ?`;
            } else {
                query += ` WHERE website_id = ?`;
                whereAdded = true;
            }
            params.push(global.currentWebsiteId);
        }
        
        // Add search filter if provided
        if (searchTerm) {
            if (whereAdded) {
                query += ` AND keyword LIKE ?`;
            } else {
                query += ` WHERE keyword LIKE ?`;
                whereAdded = true;
            }
            params.push(`%${searchTerm}%`);
        }
        
        // Add ordering and limits
        query += ` ORDER BY added_at DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        
        return await getAll(query, params);
    },
    
    // Get keywords by owner
    async getKeywordsByOwner(ownerId, status = null, limit = 100, offset = 0, searchTerm = null, websiteId = null) {
        return this.getKeywords(status, limit, offset, searchTerm, ownerId, null, websiteId);
    },
    
    // Get keywords by organization
    async getKeywordsByOrganization(organizationId, status = null, limit = 100, offset = 0, searchTerm = null, websiteId = null) {
    console.log(`Getting keywords for organization: ${organizationId}, status: ${status}, search: ${searchTerm}`);
    
    let query = `SELECT k.id, k.keyword, k.category, k.interests, k.image_url, k.full_recipe, k.status, k.recipe_id, 
       k.owner_id, k.organization_id, k.website_id, k.added_at, k.processed_at,
       u.name as owner_name, u.role as owner_role
FROM keywords k
LEFT JOIN users u ON k.owner_id = u.id`;
    
    const params = [];
    let whereAdded = false;
    
    // Add organization filter FIRST
    query += ` WHERE k.organization_id = ?`;
    params.push(organizationId);
    whereAdded = true;
    
    // Add status filter if provided
    if (status) {
        query += ` AND k.status = ?`;
        params.push(status);
    }
    
    // Add search filter if provided
    if (searchTerm) {
        query += ` AND k.keyword LIKE ?`;
        params.push(`%${searchTerm}%`);
    }
    
    // Add website filter
    if (websiteId) {
        query += ` AND k.website_id = ?`;
        params.push(websiteId);
    } else if (global.currentWebsiteId) {
        query += ` AND k.website_id = ?`;
        params.push(global.currentWebsiteId);
    }
    
    // Add ordering and limits
    query += ` ORDER BY k.added_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);
    
    const results = await getAll(query, params);
    console.log(`Retrieved ${results.length} keywords for organization ${organizationId}`);
    return results;
},
    
    // Get the count of keywords matching filters
    async getKeywordsCount(status = null, searchTerm = null, ownerId = null, organizationId = null, websiteId = null) {
        console.log(`Counting keywords with status: ${status}, owner: ${ownerId}, org: ${organizationId}`);
        
        let query = `SELECT COUNT(*) as count FROM keywords`;
        
        const params = [];
        let whereAdded = false;
        
        // If organization ID is provided, filter by it first
        if (organizationId) {
            query += ` WHERE organization_id = ?`;
            params.push(organizationId);
            whereAdded = true;
        }
        
        // Add owner filter if provided
        if (ownerId) {
            if (whereAdded) {
                query += ` AND owner_id = ?`;
            } else {
                query += ` WHERE owner_id = ?`;
                whereAdded = true;
            }
            params.push(ownerId);
        }
        
        // Add status filter if provided
        if (status) {
            if (whereAdded) {
                query += ` AND status = ?`;
            } else {
                query += ` WHERE status = ?`;
                whereAdded = true;
            }
            params.push(status);
        }
        
        // Add website filter
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            if (whereAdded) {
                query += ` AND website_id = ?`;
            } else {
                query += ` WHERE website_id = ?`;
                whereAdded = true;
            }
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            if (whereAdded) {
                query += ` AND website_id = ?`;
            } else {
                query += ` WHERE website_id = ?`;
                whereAdded = true;
            }
            params.push(global.currentWebsiteId);
        }
        
        // Add search filter if provided
        if (searchTerm) {
            if (whereAdded) {
                query += ` AND keyword LIKE ?`;
            } else {
                query += ` WHERE keyword LIKE ?`;
            }
            params.push(`%${searchTerm}%`);
        }
        
        console.log('Count SQL Query:', query);
        console.log('Count SQL Params:', params);
        
        const result = await getOne(query, params);
        console.log(`Count result:`, result);
        return result ? result.count : 0;
    },
    
    // Get a single keyword by ID
    async getKeywordById(id, websiteId = null) {
    let query = `SELECT id, keyword, category, interests, image_url, full_recipe, status, recipe_id, owner_id, organization_id, website_id, added_at, processed_at
FROM keywords 
                     WHERE id = ?`;
    let params = [id];
    
    if (websiteId) {
        query += ` AND website_id = ?`;
        params.push(websiteId);
    } else if (global.currentWebsiteId) {
        query += ` AND website_id = ?`;
        params.push(global.currentWebsiteId);
    }
    
    return await getOne(query, params);
},
    
    // Get multiple keywords by IDs
    // Get multiple keywords by IDs
async getKeywordsByIds(ids, websiteId = null) {
    if (!Array.isArray(ids) || ids.length === 0) {
        return [];
    }
    
    const placeholders = ids.map(() => '?').join(',');
    let params = [...ids];
    
    let query = `SELECT id, keyword, category, interests, image_url, full_recipe, status, recipe_id, owner_id, organization_id, website_id, added_at, processed_at
FROM keywords 
                     WHERE id IN (${placeholders})`;
    
    // Add website filter
    if (websiteId) {
        query += ` AND website_id = ?`;
        params.push(websiteId);
    } else if (global.currentWebsiteId) {
        query += ` AND website_id = ?`;
        params.push(global.currentWebsiteId);
    }
    
    query += ` ORDER BY added_at DESC`;
    
    return await getAll(query, params);
},
    
    // Replace the updateKeywordStatus function in db.js (around line 1077) with this fixed version

// FIXED: Replace the updateKeywordStatus function in keywordsDb (in db.js) with this:

async updateKeywordStatus(id, status, recipeId = null, websiteId = null) {
  try {
    console.log(`🔄 [DB] Updating keyword ${id} status to '${status}' with recipe ID: ${recipeId}`);
    
    // First, check if the keyword exists and get its current state
    const existingKeyword = await getOne(
      `SELECT id, status, website_id, organization_id FROM keywords WHERE id = ?`, 
      [id]
    );
    
    if (!existingKeyword) {
      console.error(`❌ [DB] Keyword ${id} does not exist in database`);
      return false;
    }
    
    console.log(`🔍 [DB] Current keyword state:`, existingKeyword);
    
    // Build update query
    let query;
    let params;
    
    if (status === 'processed' && recipeId) {
      query = `UPDATE keywords 
               SET status = ?, recipe_id = ?, processed_at = CURRENT_TIMESTAMP 
               WHERE id = ?`;
      params = [status, recipeId, id];
    } else {
      query = `UPDATE keywords 
               SET status = ?, processed_at = CURRENT_TIMESTAMP 
               WHERE id = ?`;
      params = [status, id];
    }
    
    // IMPORTANT: Only add website filter if the keyword actually has a website_id
    // and it matches what we're trying to update
    if (existingKeyword.website_id && websiteId && existingKeyword.website_id === websiteId) {
      query += ` AND website_id = ?`;
      params.push(websiteId);
      console.log(`🌐 [DB] Adding website filter: ${websiteId}`);
    } else if (existingKeyword.website_id && !websiteId) {
      // If keyword has a website_id but none provided, don't filter
      console.log(`⚠️ [DB] Keyword has website_id ${existingKeyword.website_id} but no filter provided`);
    } else if (!existingKeyword.website_id) {
      console.log(`ℹ️ [DB] Keyword has no website_id, proceeding without filter`);
    }
    
    console.log(`🔍 [DB] Executing query:`, query);
    console.log(`🔍 [DB] With params:`, params);
    
    const result = await runQuery(query, params);
    
    console.log(`📊 [DB] Update result:`, { 
      changes: result.changes, 
      lastID: result.lastID 
    });
    
    if (result.changes === 0) {
      console.error(`❌ [DB] No rows updated for keyword ${id}`);
      
      // Try without website filter as last resort
      let fallbackQuery;
      let fallbackParams;
      
      if (status === 'processed' && recipeId) {
        fallbackQuery = `UPDATE keywords 
                        SET status = ?, recipe_id = ?, processed_at = CURRENT_TIMESTAMP 
                        WHERE id = ?`;
        fallbackParams = [status, recipeId, id];
      } else {
        fallbackQuery = `UPDATE keywords 
                        SET status = ?, processed_at = CURRENT_TIMESTAMP 
                        WHERE id = ?`;
        fallbackParams = [status, id];
      }
      
      console.log(`🔄 [DB] Trying fallback update without website filter`);
      const fallbackResult = await runQuery(fallbackQuery, fallbackParams);
      
      if (fallbackResult.changes > 0) {
        console.log(`✅ [DB] Fallback update succeeded`);
        return true;
      } else {
        console.error(`❌ [DB] Even fallback update failed`);
        return false;
      }
    }
    
    console.log(`✅ [DB] Successfully updated keyword ${id} status to '${status}'`);
    return true;
    
  } catch (error) {
    console.error(`❌ [DB] Error updating keyword status for ${id}:`, error);
    throw error;
  }
},
    
    // Delete a keyword
    async deleteKeyword(id, websiteId = null) {
        let query = `DELETE FROM keywords WHERE id = ?`;
        let params = [id];
        
        // If websiteId is provided explicitly, use it
        if (websiteId) {
            query += ` AND website_id = ?`;
            params.push(websiteId);
        } 
        // Otherwise use the global context
        else if (global.currentWebsiteId) {
            query += ` AND website_id = ?`;
            params.push(global.currentWebsiteId);
        }
        
        await runQuery(query, params);
        return true;
    },
    
    // Delete multiple keywords with cascading deletes
    async deleteKeywords(ids, websiteId = null) {
        if (!Array.isArray(ids) || ids.length === 0) {
            return false;
        }
        
        console.log(`🗑️ [DELETE] Starting cascading delete for ${ids.length} keywords`);
        
        const placeholders = ids.map(() => '?').join(',');
        let baseParams = [...ids];
        
        let whereClause = `id IN (${placeholders})`;
        
        // Add website filtering
        if (websiteId) {
            whereClause += ` AND website_id = ?`;
            baseParams.push(websiteId);
        } else if (global.currentWebsiteId) {
            whereClause += ` AND website_id = ?`;
            baseParams.push(global.currentWebsiteId);
        }
        
        try {
            // Step 1: Delete related records first to avoid foreign key constraints
            console.log(`🗑️ [DELETE] Deleting related records...`);
            
            // Get recipe IDs for these keywords
            const recipeIds = await getAll(
                `SELECT DISTINCT recipe_id FROM keywords WHERE ${whereClause} AND recipe_id IS NOT NULL`,
                baseParams
            );
            
            if (recipeIds && recipeIds.length > 0) {
                const recipeIdList = recipeIds.map(r => r.recipe_id);
                const recipePlaceholders = recipeIdList.map(() => '?').join(',');
                
                console.log(`🗑️ [DELETE] Found ${recipeIdList.length} related recipes to clean up`);
                
                // Helper function to safely delete from table if it exists
                const safeDelete = async (tableName, whereClause, params) => {
                    try {
                        await runQuery(`DELETE FROM ${tableName} WHERE ${whereClause}`, params);
                        console.log(`🗑️ [DELETE] Deleted from ${tableName}`);
                    } catch (error) {
                        if (error.message.includes('no such table')) {
                            console.log(`⚠️ [DELETE] Table ${tableName} doesn't exist, skipping...`);
                        } else {
                            console.error(`❌ [DELETE] Error deleting from ${tableName}:`, error.message);
                            throw error;
                        }
                    }
                };
                
                // Delete related data with error handling for missing tables
                await safeDelete('recipe_images', `recipe_id IN (${recipePlaceholders})`, recipeIdList);
                await safeDelete('facebook_content', `recipe_id IN (${recipePlaceholders})`, recipeIdList);
                await safeDelete('pinterest_content', `recipe_id IN (${recipePlaceholders})`, recipeIdList);
                await safeDelete('pinterest_variations', `recipe_id IN (${recipePlaceholders})`, recipeIdList);
                await safeDelete('blog_content', `recipe_id IN (${recipePlaceholders})`, recipeIdList);
                await safeDelete('wordpress_publications', `recipe_id IN (${recipePlaceholders})`, recipeIdList);
                
                // Delete recipes last
                await safeDelete('recipes', `id IN (${recipePlaceholders})`, recipeIdList);
                console.log(`🗑️ [DELETE] Cleaned up ${recipeIdList.length} recipes and related data`);
            }
            
            // Step 2: Check for any remaining foreign key references before deleting keywords
            console.log(`🔍 [DELETE] Checking for remaining foreign key references...`);
            
            // Check common tables that might reference keywords
            const possibleReferences = [
                'recipes', 'facebook_content', 'pinterest_content', 'pinterest_variations', 
                'blog_content', 'recipe_images', 'wordpress_publications', 'activities',
                'image_queue', 'cleanup_logs'
            ];
            
            for (const keywordId of ids) {
                console.log(`🔍 [DELETE] Checking references for keyword ${keywordId}:`);
                
                // Check each possible table
                for (const tableName of possibleReferences) {
                    try {
                        // Try different possible foreign key column names
                        const possibleColumns = ['keyword_id', 'related_keyword_id', 'source_keyword_id'];
                        
                        for (const columnName of possibleColumns) {
                            try {
                                const refs = await getAll(
                                    `SELECT COUNT(*) as count FROM ${tableName} WHERE ${columnName} = ?`,
                                    [keywordId]
                                );
                                
                                if (refs && refs[0] && refs[0].count > 0) {
                                    console.log(`⚠️ [DELETE] Found ${refs[0].count} references in ${tableName}.${columnName} for keyword ${keywordId}`);
                                    
                                    // Try to delete these references
                                    await runQuery(`DELETE FROM ${tableName} WHERE ${columnName} = ?`, [keywordId]);
                                    console.log(`🗑️ [DELETE] Cleaned up references in ${tableName}.${columnName}`);
                                }
                            } catch (colError) {
                                // Column doesn't exist, continue
                                if (!colError.message.includes('no such column')) {
                                    console.log(`⚠️ [DELETE] Error checking ${tableName}.${columnName}:`, colError.message);
                                }
                            }
                        }
                    } catch (tableError) {
                        // Table doesn't exist, continue
                        if (!tableError.message.includes('no such table')) {
                            console.log(`⚠️ [DELETE] Error checking table ${tableName}:`, tableError.message);
                        }
                    }
                }
            }
            
            // Step 3: Get SQLite foreign key information before attempting delete
            console.log(`🔍 [DELETE] Getting foreign key constraints for keywords table...`);
            try {
                const fkInfo = await getAll(`PRAGMA foreign_key_list(keywords)`);
                if (fkInfo && fkInfo.length > 0) {
                    console.log(`📋 [DELETE] Foreign keys on keywords table:`, fkInfo);
                } else {
                    console.log(`ℹ️ [DELETE] No foreign keys found on keywords table`);
                }
            } catch (fkError) {
                console.log(`⚠️ [DELETE] Could not get foreign key info:`, fkError.message);
            }
            
            // Try to get all table names and check which ones reference keywords
            console.log(`🔍 [DELETE] Getting all tables in database...`);
            try {
                const tables = await getAll(`SELECT name FROM sqlite_master WHERE type='table'`);
                console.log(`📋 [DELETE] Found tables:`, tables.map(t => t.name));
                
                // For each table, check its foreign keys
                for (const table of tables) {
                    try {
                        const tableFKs = await getAll(`PRAGMA foreign_key_list(${table.name})`);
                        if (tableFKs && tableFKs.length > 0) {
                            const keywordFKs = tableFKs.filter(fk => fk.table === 'keywords');
                            if (keywordFKs.length > 0) {
                                console.log(`🎯 [DELETE] Table ${table.name} has foreign keys to keywords:`, keywordFKs);
                                
                                // Check if this table has references to our keyword
                                for (const keywordId of ids) {
                                    for (const fk of keywordFKs) {
                                        try {
                                            const refs = await getAll(
                                                `SELECT COUNT(*) as count FROM ${table.name} WHERE ${fk.from} = ?`,
                                                [keywordId]
                                            );
                                            if (refs && refs[0] && refs[0].count > 0) {
                                                console.log(`💥 [DELETE] FOUND THE CULPRIT! ${table.name}.${fk.from} has ${refs[0].count} references to keyword ${keywordId}`);
                                                
                                                // Delete these references
                                                await runQuery(`DELETE FROM ${table.name} WHERE ${fk.from} = ?`, [keywordId]);
                                                console.log(`🗑️ [DELETE] Cleaned up references in ${table.name}.${fk.from}`);
                                            }
                                        } catch (refError) {
                                            console.log(`⚠️ [DELETE] Error checking ${table.name}.${fk.from}:`, refError.message);
                                        }
                                    }
                                }
                            }
                        }
                    } catch (tableError) {
                        // Skip tables we can't access
                    }
                }
            } catch (tablesError) {
                console.log(`⚠️ [DELETE] Could not get table list:`, tablesError.message);
            }
            
            // Step 4: Now try to delete the keywords
            console.log(`🗑️ [DELETE] Attempting to delete keywords after cleaning all references...`);
            let query = `DELETE FROM keywords WHERE ${whereClause}`;
            await runQuery(query, baseParams);
            
            console.log(`✅ [DELETE] Successfully deleted ${ids.length} keywords and all related data`);
            return true;
            
        } catch (error) {
            console.error(`❌ [DELETE] Error during cascading delete:`, error.message);
            throw error;
        }
    },

    // NEW FILTERED FUNCTION FROM SECOND FILE

    // Get the count of keywords matching filters with date filtering
    async getKeywordsCountFiltered(status = null, searchTerm = null, ownerId = null, organizationId = null, dateFilter = null, websiteId = null) {
    console.log(`Counting filtered keywords with status: ${status}, owner: ${ownerId}, org: ${organizationId}`);
    
    let query = `SELECT COUNT(*) as count FROM keywords`;
    
    const params = [];
    let whereAdded = false;
    
    // If organization ID is provided, filter by it first
    if (organizationId) {
        query += ` WHERE organization_id = ?`;
        params.push(organizationId);
        whereAdded = true;
    }
    
    // Add owner filter if provided
    if (ownerId) {
        if (whereAdded) {
            query += ` AND owner_id = ?`;
        } else {
            query += ` WHERE owner_id = ?`;
            whereAdded = true;
        }
        params.push(ownerId);
    }
    
    // Add status filter if provided
    if (status) {
        if (whereAdded) {
            query += ` AND status = ?`;
        } else {
            query += ` WHERE status = ?`;
            whereAdded = true;
        }
        params.push(status);
    }
    
    // FIXED: Add proper date filtering with datetime comparison
    if (dateFilter) {
        // Choose the right date column based on status
        let dateColumn = 'added_at'; // Default for pending/new keywords
        if (status === 'processed' || status === 'failed') {
            dateColumn = 'processed_at'; // Use processed_at for completed keywords
        }
        
        if (dateFilter.startDate) {
            if (whereAdded) {
                query += ` AND datetime(${dateColumn}) >= datetime(?)`;
            } else {
                query += ` WHERE datetime(${dateColumn}) >= datetime(?)`;
                whereAdded = true;
            }
            params.push(dateFilter.startDate.toISOString());
        }
        if (dateFilter.endDate) {
            if (whereAdded) {
                query += ` AND datetime(${dateColumn}) <= datetime(?)`;
            } else {
                query += ` WHERE datetime(${dateColumn}) <= datetime(?)`;
                whereAdded = true;
            }
            params.push(dateFilter.endDate.toISOString());
        }
    }
    
    // Add website filter
    if (websiteId) {
        if (whereAdded) {
            query += ` AND website_id = ?`;
        } else {
            query += ` WHERE website_id = ?`;
            whereAdded = true;
        }
        params.push(websiteId);
    } else if (global.currentWebsiteId) {
        if (whereAdded) {
            query += ` AND website_id = ?`;
        } else {
            query += ` WHERE website_id = ?`;
            whereAdded = true;
        }
        params.push(global.currentWebsiteId);
    }
    
    // Add search filter if provided
    if (searchTerm) {
        if (whereAdded) {
            query += ` AND keyword LIKE ?`;
        } else {
            query += ` WHERE keyword LIKE ?`;
        }
        params.push(`%${searchTerm}%`);
    }
    
    console.log('Filtered keyword count query:', query);
    console.log('Filtered keyword count params:', params);
    
    const result = await getOne(query, params);
    console.log(`Filtered keyword count result:`, result);
    return result ? result.count : 0;
},
};

// In keywordsDb.addKeyword and addKeywordsBatch
const validateImageUrl = (imageUrl) => {
  if (!imageUrl) return null;
  
  // If it's a filename only, prepend the path
  if (!imageUrl.includes('/') && !imageUrl.startsWith('http')) {
    return `/recipe_images/${imageUrl}`;
  }
  
  return imageUrl;
};

// WordPress publication count with date filtering
const wordpressDbFiltered = {
    async getPublicationCountFiltered(userId = null, organizationId = null, websiteId = null, dateFilter = null) {
        try {
            // First check if the wordpress_publications table exists
            const tableCheck = await getOne(`
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='wordpress_publications'
            `);
            
            if (!tableCheck) {
                return 0;
            }
            
            let query = `
                SELECT COUNT(*) as count
                FROM wordpress_publications wp
                JOIN recipes r ON wp.recipe_id = r.id
            `;
            
            const params = [];
            let whereAdded = false;
            
            // Add organization filter
            if (organizationId) {
                query += ` WHERE r.organization_id = ?`;
                params.push(organizationId);
                whereAdded = true;
            }
            
            // Add user filter
            if (userId) {
                if (whereAdded) {
                    query += ` AND r.owner_id = ?`;
                } else {
                    query += ` WHERE r.owner_id = ?`;
                    whereAdded = true;
                }
                params.push(userId);
            }
            
            // Add website filter
            if (websiteId) {
                if (whereAdded) {
                    query += ` AND wp.website_id = ?`;
                } else {
                    query += ` WHERE wp.website_id = ?`;
                    whereAdded = true;
                }
                params.push(websiteId);
            } else if (global.currentWebsiteId) {
                if (whereAdded) {
                    query += ` AND wp.website_id = ?`;
                } else {
                    query += ` WHERE wp.website_id = ?`;
                    whereAdded = true;
                }
                params.push(global.currentWebsiteId);
            }
            
            // FIXED: Add proper date filtering with datetime comparison
            if (dateFilter) {
                if (dateFilter.startDate) {
                    if (whereAdded) {
                        query += ` AND datetime(wp.created_at) >= datetime(?)`;
                    } else {
                        query += ` WHERE datetime(wp.created_at) >= datetime(?)`;
                        whereAdded = true;
                    }
                    params.push(dateFilter.startDate.toISOString());
                }
                if (dateFilter.endDate) {
                    if (whereAdded) {
                        query += ` AND datetime(wp.created_at) <= datetime(?)`;
                    } else {
                        query += ` WHERE datetime(wp.created_at) <= datetime(?)`;
                        whereAdded = true;
                    }
                    params.push(dateFilter.endDate.toISOString());
                }
            }
            
            console.log('WordPress filtered count query:', query);
            console.log('WordPress filtered count params:', params);
            
            const result = await getOne(query, params);
            return result ? result.count : 0;
        } catch (error) {
            console.error('Error getting filtered WordPress publication count:', error);
            return 0;
        }
    }
};

// Export all database operations
module.exports = {
    runQuery,
    getOne,
    getAll,
    recipeDb,
    facebookDb,
    pinterestDb,
    blogDb,
    keywordsDb,
    wordpressDbFiltered,
    close: () => {
        db.close();
    }
};