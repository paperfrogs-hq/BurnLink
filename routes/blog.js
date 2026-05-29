const express = require("express");
const router = express.Router();
const BlogPost = require("../models/BlogPost");
const { validators } = require("../lib/security");

// Middleware to track analytics
const trackAnalytics = async (req, res, next) => {
  try {
    const supabase = require("../lib/supabase");
    const postSlug = req.params.slug;

    if (postSlug) {
      const { data: post } = await supabase
        .from("blog_posts")
        .select("id")
        .eq("slug", postSlug)
        .single();

      if (post) {
        await supabase.from("blog_analytics").insert([
          {
            post_id: post.id,
            visitor_ip: req.ip,
            referrer: req.get("referrer"),
          },
        ]);
      }
    }
  } catch (err) {
    console.error("Analytics tracking error:", err);
  }
  next();
};

// --- PUBLIC ROUTES ---

// Get all published blog posts with pagination - optimized
router.get("/", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const category = req.query.category || null;
    const limit = 10;
    const offset = (page - 1) * limit;

    // Set caching headers for first page only
    if (page === 1) {
      res.set({
        "Cache-Control": "public, max-age=600", // 10 minutes
        "X-Content-Type-Options": "nosniff",
      });
    }

    let query = require("../lib/supabase")
      .from("blog_posts")
      .select("id, title, slug, excerpt, category, author, published_at, featured_image, reading_time, views_count, featured", { count: "exact" })
      .eq("status", "published")
      .order("published_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (category) {
      query = query.eq("category", category);
    }

    const { data: posts, count, error } = await query;

    if (error) throw error;

    const totalPages = Math.ceil(count / limit);

    res.render("blog/index", {
      posts,
      currentPage: page,
      totalPages,
      category,
      activePage: "blog",
      cspNonce: res.locals.cspNonce,
    });
  } catch (err) {
    console.error("Error fetching blog posts:", err);
    res.status(500).render("not-found", {
      message: "Failed to load blog posts",
      activePage: "blog",
    });
  }
});

// Get featured blog posts
router.get("/featured", async (req, res) => {
  try {
    const posts = await BlogPost.getAll({
      status: "published",
      featured: true,
      limit: 6,
    });

    res.json(posts);
  } catch (err) {
    console.error("Error fetching featured posts:", err);
    res.status(500).json({ error: "Failed to fetch featured posts" });
  }
});

// Get blog categories
router.get("/categories", async (req, res) => {
  try {
    const supabase = require("../lib/supabase");
    
    // Cache categories for 1 hour since they change infrequently
    res.set({
      "Cache-Control": "public, max-age=3600",
      "X-Content-Type-Options": "nosniff",
    });

    const { data, error } = await supabase
      .from("blog_posts")
      .select("category")
      .eq("status", "published")
      .distinct();

    if (error) throw error;

    const categories = data
      ?.map((item) => item.category)
      .filter((v, i, a) => a.indexOf(v) === i)
      .sort() || [];

    res.json(categories);
  } catch (err) {
    console.error("Error fetching categories:", err);
    res.status(500).json({ error: "Failed to fetch categories" });
  }
});

// Get single blog post by slug
router.get("/:slug", trackAnalytics, async (req, res) => {
  try {
    const post = await BlogPost.getBySlug(req.params.slug);

    if (!post) {
      return res.status(404).render("not-found", {
        message: "Blog post not found",
        activePage: "blog",
      });
    }

    // Update view count
    await require("../lib/supabase")
      .from("blog_posts")
      .update({ views_count: (post.views_count || 0) + 1 })
      .eq("id", post.id);

    // Get related posts
    const relatedPosts = await BlogPost.getRelated(post.category, post.slug, 3);

    res.render("blog/post", {
      post,
      relatedPosts,
      activePage: "blog",
    });
  } catch (err) {
    console.error("Error fetching blog post:", err);
    res.status(500).render("not-found", {
      message: "Error loading blog post",
      activePage: "blog",
    });
  }
});

// Search blog posts - optimized with caching
router.get("/search/posts", async (req, res) => {
  try {
    const searchQuery = req.query.q;

    if (!searchQuery || searchQuery.length < 2) {
      return res.json([]);
    }

    // Set caching headers - cache for 5 minutes for repeated queries
    res.set({
      "Cache-Control": "public, max-age=300",
      "X-Content-Type-Options": "nosniff",
    });

    const posts = await BlogPost.searchPosts(searchQuery);
    
    // Return only necessary fields to reduce payload and speed up transfer
    const optimizedResults = posts.slice(0, 15).map(post => ({
      title: post.title,
      slug: post.slug,
      excerpt: post.excerpt,
      category: post.category,
      author: post.author,
      published_at: post.published_at,
    }));

    res.json(optimizedResults);
  } catch (err) {
    console.error("Error searching posts:", err);
    res.status(500).json({ error: "Search failed" });
  }
});

// --- ADMIN ROUTES ---

// Simple token test endpoint (no database needed)
router.post("/admin/test-token", (req, res) => {
  const adminToken = process.env.BLOG_ADMIN_TOKEN;
  const authHeader = req.headers.authorization;

  console.log("\n🔐 Admin Login Attempt:");
  console.log("   Token in .env:", adminToken ? "SET ✓" : "NOT SET ✗");
  console.log("   Auth header:", authHeader ? "SENT ✓" : "MISSING ✗");

  if (!adminToken) {
    console.log("   ❌ FAIL: BLOG_ADMIN_TOKEN not set in .env\n");
    return res.status(500).json({ 
      error: "Wrong Password",
      debug: "Add BLOG_ADMIN_TOKEN=your-token to .env file"
    });
  }

  if (!authHeader) {
    console.log("   ❌ FAIL: No Authorization header\n");
    return res.status(401).json({ error: "No authorization header" });
  }

  if (!authHeader.startsWith("Bearer ")) {
    console.log("   ❌ FAIL: Header format wrong (should be 'Bearer token')\n");
    return res.status(401).json({ error: "Invalid header format (use Bearer)" });
  }

  const providedToken = authHeader.slice(7).trim();
  const envToken = adminToken.trim();
  
  console.log("   Provided token length:", providedToken.length);
  console.log("   Expected token length:", envToken.length);
  console.log("   First 15 chars match:", providedToken.substring(0, 15) === envToken.substring(0, 15));

  if (providedToken !== envToken) {
    console.log("   ❌ FAIL: Token mismatch\n");
    return res.status(401).json({ error: "Invalid token" });
  }

  console.log("   ✅ SUCCESS: Token valid!\n");
  res.json({ success: true, message: "Token is valid" });
});

// Check if admin (basic auth check)
const adminAuth = (req, res, next) => {
  const adminToken = process.env.BLOG_ADMIN_TOKEN;
  const authHeader = req.headers.authorization;

  if (
    !adminToken ||
    !authHeader ||
    !authHeader.startsWith("Bearer ") ||
    authHeader.slice(7) !== adminToken
  ) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  next();
};

// Get admin dashboard
router.get("/admin/dashboard", adminAuth, async (req, res) => {
  try {
    const allPosts = await BlogPost.getAll({ status: "published" });
    const draftPosts = await BlogPost.getAll({ status: "draft" });

    const supabase = require("../lib/supabase");
    const { data: analytics } = await supabase
      .from("blog_analytics")
      .select("*", { count: "exact" });

    const totalViews = allPosts.reduce((sum, post) => sum + (post.views_count || 0), 0);

    res.json({
      totalPosts: allPosts.length,
      draftPosts: draftPosts.length,
      totalViews,
      analyticsCount: analytics?.length || 0,
    });
  } catch (err) {
    console.error("Error fetching dashboard:", err);
    res.status(500).json({ error: "Failed to fetch dashboard data" });
  }
});

// Create new blog post
router.post("/admin/posts", adminAuth, async (req, res) => {
  try {
    const { title, slug, excerpt, content, category, status, featured, author, tags, featured_image } = req.body;

    console.log("Creating post with data:", { title, slug, excerpt, content: content ? content.substring(0, 50) : "", category, status, featured, author, tags, featured_image });

    if (!title || !content || !category) {
      console.log("Missing required fields:", { title: !!title, content: !!content, category: !!category });
      return res.status(400).json({ error: "Missing required fields: title, content, category" });
    }

    const post = await BlogPost.create({
      title,
      slug,
      excerpt,
      content,
      category,
      status,
      featured,
      author: author || "BurnLink Team",
      tags,
      featured_image,
    });

    console.log("Post created successfully:", post.id);
    res.status(201).json(post);
  } catch (err) {
    console.error("Error creating post - FULL ERROR:", err.message);
    console.error("Error details:", err);
    res.status(500).json({ error: `Failed to create post: ${err.message}` });
  }
});

// Update blog post
router.put("/admin/posts/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, slug, excerpt, content, category, status, featured, author, tags, featured_image } = req.body;

    const post = await BlogPost.update(id, {
      title: title && validators.sanitizeInput(title),
      slug,
      excerpt: excerpt && validators.sanitizeInput(excerpt),
      content: content && validators.sanitizeInput(content),
      category,
      status,
      featured,
      author,
      tags,
      featured_image,
      published_at: status === "published" ? new Date().toISOString() : null,
    });

    res.json(post);
  } catch (err) {
    console.error("Error updating post:", err);
    res.status(500).json({ error: "Failed to update post" });
  }
});

// Delete blog post
router.delete("/admin/posts/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await BlogPost.delete(id);
    res.json({ success: true });
  } catch (err) {
    console.error("Error deleting post:", err);
    res.status(500).json({ error: "Failed to delete post" });
  }
});

// Get all posts (admin view)
router.get("/admin/posts", adminAuth, async (req, res) => {
  try {
    const status = req.query.status || null;
    const posts = await BlogPost.getAll({ status });
    res.json(posts);
  } catch (err) {
    console.error("Error fetching admin posts:", err);
    res.status(500).json({ error: "Failed to fetch posts" });
  }
});

// ── ANALYTICS ──

// Get detailed analytics overview
router.get("/admin/analytics", adminAuth, async (req, res) => {
  try {
    const supabase = require("../lib/supabase");

    // Get all published posts with view data
    const { data: posts } = await supabase
      .from("blog_posts")
      .select("*")
      .eq("status", "published")
      .order("published_at", { ascending: false });

    // Get analytics data
    const { data: analyticsRaw } = await supabase
      .from("blog_analytics")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(1000);

    // Calculate stats
    const totalViews = posts.reduce((sum, post) => sum + (post.views_count || 0), 0);
    const totalPosts = posts.length;
    const totalAnalyticsEvents = analyticsRaw?.length || 0;

    // Get top posts by views
    const topPosts = posts
      .sort((a, b) => (b.views_count || 0) - (a.views_count || 0))
      .slice(0, 5)
      .map(post => ({
        title: post.title,
        slug: post.slug,
        views: post.views_count || 0,
        category: post.category,
      }));

    // Get views by category
    const viewsByCategory = {};
    posts.forEach(post => {
      if (!viewsByCategory[post.category]) {
        viewsByCategory[post.category] = 0;
      }
      viewsByCategory[post.category] += post.views_count || 0;
    });

    // Get posts by category count
    const postsByCategory = {};
    posts.forEach(post => {
      if (!postsByCategory[post.category]) {
        postsByCategory[post.category] = 0;
      }
      postsByCategory[post.category] += 1;
    });

    // Analytics events over time (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const eventsOverTime = {};
    const dateRange = [];
    for (let i = 29; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      dateRange.push(dateStr);
      eventsOverTime[dateStr] = 0;
    }

    analyticsRaw?.forEach(event => {
      const dateStr = new Date(event.created_at).toISOString().split('T')[0];
      if (eventsOverTime[dateStr] !== undefined) {
        eventsOverTime[dateStr] += 1;
      }
    });

    const eventsByDate = dateRange.map(date => ({
      date,
      events: eventsOverTime[date] || 0,
    }));

    res.json({
      summary: {
        totalPosts,
        totalViews,
        totalAnalyticsEvents,
        averageViewsPerPost: totalPosts > 0 ? Math.round(totalViews / totalPosts) : 0,
      },
      topPosts,
      viewsByCategory,
      postsByCategory,
      eventsByDate,
    });
  } catch (err) {
    console.error("Error fetching analytics:", err);
    res.status(500).json({ error: "Failed to fetch analytics data" });
  }
});

// ── COMMENTS ──

// Get comments for a post
router.get("/:slug/comments", async (req, res) => {
  try {
    const { data: post } = await require("../lib/supabase")
      .from("blog_posts")
      .select("id")
      .eq("slug", req.params.slug)
      .single();

    if (!post) {
      return res.status(404).json({ error: "Post not found" });
    }

    const comments = await BlogPost.getComments(post.id);
    res.json(comments);
  } catch (err) {
    console.error("Error fetching comments:", err);
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});

// Add comment to a post
router.post("/:slug/comments", async (req, res) => {
  try {
    const { authorName, authorEmail, content } = req.body;

    if (!authorName || !authorEmail || !content) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const { data: post } = await require("../lib/supabase")
      .from("blog_posts")
      .select("id")
      .eq("slug", req.params.slug)
      .single();

    if (!post) {
      return res.status(404).json({ error: "Post not found" });
    }

    const comment = await BlogPost.addComment(post.id, authorName, authorEmail, content);
    res.status(201).json({ 
      success: true, 
      message: "Comment submitted for review",
      comment 
    });
  } catch (err) {
    console.error("Error adding comment:", err);
    res.status(500).json({ error: "Failed to add comment" });
  }
});

// Admin: Get pending comments
router.get("/admin/comments", adminAuth, async (req, res) => {
  try {
    const supabase = require("../lib/supabase");
    const { data, error } = await supabase
      .from("blog_comments")
      .select("*, blog_posts(id, title, slug)")
      .eq("approved", false)
      .order("created_at", { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error("Error fetching pending comments:", err);
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});

// Admin: Approve comment
router.post("/admin/comments/:id/approve", adminAuth, async (req, res) => {
  try {
    await BlogPost.approveComment(req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error("Error approving comment:", err);
    res.status(500).json({ error: "Failed to approve comment" });
  }
});

// Admin: Delete comment
router.delete("/admin/comments/:id", adminAuth, async (req, res) => {
  try {
    await BlogPost.deleteComment(req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error("Error deleting comment:", err);
    res.status(500).json({ error: "Failed to delete comment" });
  }
});

module.exports = router;
