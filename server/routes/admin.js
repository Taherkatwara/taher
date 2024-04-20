const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Post = require('../models/Post');

const adminlayout = '../views/layouts/admin';
const JwtSecret = process.env.JWT_SECRET;

const authMiddleware = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: 'unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, JwtSecret);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ message: 'unauthorized' });
    }
};

router.get('/admin', async (req, res) => {
    try {
        const locals = {
            title: 'admin',
            description: 'simple blog about ejs and mongodb'
        };
        res.render('admin/index', { locals, layout: adminlayout });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'internal server error' });
    }
});

router.post('/admin', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'invalid username' });
        }
        const ispasswordvalid = await bcrypt.compare(password, user.password);
        if (!ispasswordvalid) {
            return res.status(401).json({ message: 'invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, JwtSecret)
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/dashboard');
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'internal server error' });
    }
});

router.get('/dashboard', authMiddleware, async (req, res) => {
    try {
        const locals = {
            title: 'dashboard',
            description: 'simple blog created'
        };
        const data = await Post.find();
        res.render('admin/dashboard', { locals, data });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'internal server error' });
    }
});

router.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        // const hashedpassword  = await bcrypt.hash(password, 10);
        try {
            const user = await User.create({ username, password })
            res.status(201).json({ message: 'user created', user });
        }
        catch (error) {
            if (error.code === 11000) {
                res.status(409).json({ message: 'user already created' });
            }
            else {
                res.status(500).json({ message: 'internal server eror' })
            }
        }
    }
    catch (error) {
        console.log(error);
    }
});

router.get('/add-post', authMiddleware, async (req, res) => {
    try {
        const locals = {
            title: 'add-post',
            description: 'simple blog created'
        }
        const data = await post.findOne();
        res.render('admin/add-post', {
            locals,
            layout: adminlayout
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'internal server error' });
    }
});

router.post('/add-post', authMiddleware, async (req, res) => {
    try {

        try {
            const newpost = new Post({
                title: req.body.title,
                body: req.body.body

            });
            await Post.create(newpost);
            res.redirect('/dashboard');
        } catch (error) {
        }
    } catch (error) {
    }
});

// Route to edit a post
router.get('/edit-post/:id', authMiddleware, async (req, res) => {
    try {
        const postId = req.params.id;
        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }
        const locals = {
            title: 'Edit Post',
            description: 'Edit Post',
            post: post
        };
        res.render('admin/edit-post', { locals, layout: adminlayout });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'internal server error' });
    }
});

// Route to update a post
router.put('/edit-post/:id', authMiddleware, async (req, res) => {
    try {
        const postId = req.params.id;
        const { title, body } = req.body;
        const updatedPost = await Post.findByIdAndUpdate(postId, { title, body }, { new: true });
        res.redirect('/dashboard');
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'internal server error' });
    }
});

// Route to render the form for editing a post
// Route to render the form for editing a post
router.get('/edit-post/:id', authMiddleware, async (req, res) => {
  try {
      const postId = req.params.id;
      const post = await Post.findById(postId);
      if (!post) {
          return res.status(404).json({ message: 'Post not found' });
      }
      const locals = {
          title: 'Edit Post',
          description: 'Edit Post',
          post: post // Passing the post object to the view
      };
      res.render('admin/edit-post', locals); // Passing locals directly to the render function
  } catch (error) {
      console.log(error);
      res.status(500).json({ message: 'Internal server error' });
  }
});



// Route to delete a post
router.delete('/delete-post/:id', authMiddleware, async (req, res) => {
    try {
        const postId = req.params.id;
        await Post.findByIdAndDelete(postId);
        res.redirect('/dashboard');
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'internal server error' });
    }
});

module.exports = router;
