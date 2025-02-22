const express = require("express");
const Blog = require("../models/Blogs.Model");
const jwt = require("jsonwebtoken");

const router = express.Router();

// Middleware for Authentication
const authenticate = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ message: "Access Denied" });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ message: "Invalid Token" });
  }
};

// Create Blog
router.post("/", authenticate, async (req, res) => {
  const { title, content } = req.body;
  const newBlog = new Blog({ title, content, createdBy: req.user.id });
  await newBlog.save();
  res.status(201).json(newBlog);
});

// Get All Blogs
router.get("/", async (req, res) => {
  const blogs = await Blog.find().populate("createdBy", "name email");
  res.json(blogs);
});

// Update Blog
router.put("/:id", authenticate, async (req, res) => {
  const blog = await Blog.findById(req.params.id);
  if (!blog) return res.status(404).json({ message: "Blog not found" });

  if (blog.createdBy.toString() !== req.user.id)
    return res.status(403).json({ message: "Not authorized" });

  blog.title = req.body.title || blog.title;
  blog.content = req.body.content || blog.content;
  await blog.save();
  res.json(blog);
});

// Delete Blog
router.delete("/:id", authenticate, async (req, res) => {
  const blog = await Blog.findById(req.params.id);
  if (!blog) return res.status(404).json({ message: "Blog not found" });

  if (blog.createdBy.toString() !== req.user.id)
    return res.status(403).json({ message: "Not authorized" });

  await blog.remove();
  res.json({ message: "Blog deleted" });
});

module.exports = router;
