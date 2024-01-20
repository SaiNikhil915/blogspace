import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import User from './Schema/User.js';
import Blog from './Schema/Blog.js';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import admin from 'firebase-admin';
import serviceAccounKey from './reactjsblogapplication-firebase-adminsdk-tupem-45d02b4c5a.json' assert { type: "json" };
import { getAuth } from 'firebase-admin/auth';
import aws from 'aws-sdk';
import 'dotenv/config';
import Notification from './Schema/Notification.js';
import Comment from './Schema/Comment.js';




const server = express();

let port = process.env.PORT || 3000;

admin.initializeApp({
    credential: admin.credential.cert(serviceAccounKey),
})

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

server.use(express.json());
server.use(cors());

mongoose.connect(process.env.DB_LOCATION, {
    autoIndex: true
});


const s3 = new aws.S3({
    region: 'ap-south-1',
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});


const generateUploadURL = async () => {
    const date = new Date();
    const imageName = `${nanoid(10)}-${date.getTime()}.jpeg`;

    return await s3.getSignedUrlPromise('putObject', {
        Bucket: 'reactjsbloggingapplication',
        Key: imageName,
        Expires: 1000,
        ContentType: 'image/jpeg',
    });
}

const verifyJWT = (req, res, next) => {
    const authorHeader = req.headers['authorization'];
    const token = authorHeader && authorHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ error: "No access token" });
    }

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ "error": "access token is invalid" });
        }
        req.user = user._id;
        next();
    });

    console.log('User ID:', req.user);
};




const formatDatatoSend = (user) => {

    const access_token = jwt.sign({ _id: user._id }, process.env.SECRET_ACCESS_KEY);

    return {
        access_token,
        profile_img: user.personal_info.profile_img,
        fullname: user.personal_info.fullname,
        username: user.personal_info.username,
    }
}

const generateUsername = async (email) => {

    let username = email.split("@")[0];
    let isUsernameNotUnique = await User.findOne({ "personal_info.username": username }).then((result) => result);
    isUsernameNotUnique ? username += nanoid(3) : "";

    return username;

}



server.get('/get-upload-url', async (req, res) => {
    generateUploadURL().then(url => {
        res.status(200).json({ uploadURL: url });
    })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        });
});



server.post("/signup", (req, res) => {

    let { fullname, email, password } = req.body;


    if (!fullname || !email || !password) {
        return res.status(403).json({ error: "Please fill all the fields" });
    }
    if (fullname.length < 3) {
        return res.status(403).json({ error: "Fullname must be atleast 3 characters long" });
    }
    if (!emailRegex.test(email)) {
        return res.status(403).json({ error: "Enter a valid email" });
    }
    if (!passwordRegex.test(password)) {
        return res.status(403).json({ error: "Password must be atleast 6 characters long and contain atleast one uppercase letter, one lowercase letter and one number" });
    }

    bcrypt.hash(password, 10, async (err, hashed_password) => {

        let username = await generateUsername(email);

        let user = new User({
            personal_info: {
                fullname,
                email,
                username,
                password: hashed_password,
            },
        });

        user.save()
            .then((u) => {
                return res.status(200).json(formatDatatoSend(u));
            })
            .catch((err) => {

                if (err.code === 11000) {
                    return res.status(500).json({ error: "Email already exists" });
                }
            });
    });
});

server.post("/signin", (req, res) => {

    let { email, password } = req.body;


    User.findOne({ "personal_info.email": email })
        .then((user) => {
            if (!user) {
                return res.status(404).json({ error: "Email not found" });
            }

            if (!user.google_auth) {

                bcrypt.compare(password, user.personal_info.password, (err, result) => {

                    if (err) {
                        return res.status(403).json({ error: err.message });
                    }

                    if (!result) {
                        return res.status(403).json({ error: "Incorrect password" });
                    }

                    else {
                        return res.status(200).json(formatDatatoSend(user));
                    }
                });

            }
            else {
                return res.status(403).json({ error: "Email was signed up with google. please log in with google to access your account" });
            }


        })
        .catch((err) => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        });
});

server.post("/google-auth", async (req, res) => {

    let { access_token } = req.body;

    getAuth()
        .verifyIdToken(access_token)
        .then(async (decodedUser) => {

            let { email, name, picture } = decodedUser;

            picture = picture.replace("s96-c", "s400-c");

            let user = await User.findOne({ "personal_info.email": email }).select("personal_info:fullname personal_info.username personal_info.profile_img google_auth").then((u) => {
                return u || null;
            })
                .catch((err) => {
                    return res.status(500).json({ error: err.message });
                });

            if (user) {
                if (!user.google_auth) {
                    return res.status(403).json({ error: "Email was signed up without google. please log in with password to access your account" });
                }
            }
            else {

                let username = await generateUsername(email);

                user = new User({
                    personal_info: {
                        fullname: name,
                        email,
                        username,
                    },
                    google_auth: true,
                });

                await user.save()
                    .then((u) => {
                        user = u;
                    })
                    .catch((err) => {
                        return res.status(500).json({ error: err.message });
                    });
            }

            return res.status(200).json(formatDatatoSend(user));





        })
        .catch((err) => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        });
});


server.post("/get-profile", (req, res) => {
    let { username } = req.body;

    User.findOne({ "personal_info.username": username })
        .select("-personal_info.password -google_auth -updatedAt -blogs  -_id")

        .then(user => {
            return res.status(200).json(user);
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        })

})



server.get("/latest-blogs", (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const blogsPerPage = 5;

    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        .then((blogs) => {
            // Calculate the starting index for the current page
            const startIndex = (page - 1) * blogsPerPage;

            // Extract the blogs for the current page
            const pageBlogs = blogs.slice(startIndex, startIndex + blogsPerPage);

            return res.status(200).json(pageBlogs);
        })
        .catch((err) => {
            return res.status(500).json({ error: err.message });
        });
});





server.get("/trending-blogs", (req, res) => {

    let maxLimit = 5;

    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username  personal_info.fullname -_id")
        .sort({ "activity.total_read": -1, "activity.total_likes": -1, "publishedAt": -1 })
        .select("blog_id title publishedAt -_id")
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json(blogs);
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });
});



server.post("/search-blogs", (req, res) => {
    let { tag } = req.body;

    let findQuery = { tags: tag, draft: false };

    let maxLimit = 5;

    Blog.find(findQuery)
        .populate("author", "personal_info.profile_img personal_info.username  personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        .limit(maxLimit)
        .then((blogs) => {
            return res.status(200).json(blogs);
        })
        .catch((err) => {
            return res.status(500).json({ error: err.message });
        });

});


server.post("/get-user-blogs", async (req, res) => {
    try {
        const { username } = req.body;

        const user = await User.findOne({ "personal_info.username": username });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const blogs = await Blog.find({ author: user._id, draft: false })
            .populate("author", "personal_info.profile_img personal_info.username  personal_info.fullname -_id")
            .sort({ "publishedAt": -1 })
            .select("blog_id title des banner activity tags publishedAt -_id");

        return res.status(200).json(blogs);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});


server.post("/get-blog", async (req, res) => {
    try {
        const { blog_id } = req.body;
        const incrementalVal = 1;

        // Find and update the blog
        const blog = await Blog.findOneAndUpdate(
            { blog_id },
            { $inc: { "activity.total_reads": incrementalVal } }
        )
            .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname ")
            .select("title des banner content activity tags publishedAt blog_id");

        // If the blog is not found, return a 404 response
        if (!blog) {
            return res.status(404).json({ error: 'Blog not found' });
        }

        // Find and update the user
        await User.findOneAndUpdate(
            { "personal_info.username": blog.author.personal_info.username },
            { $inc: { "account_info.total_reads": incrementalVal } }
        );

        // Send the blog data in the response
        res.status(200).json({ blog });
    } catch (err) {
        console.error("Error fetching blog:", err);
        res.status(500).json({ error: err.message });
    }
});



server.post("/search-users", (req, res) => {
    let { query } = req.body;

    User.find({ "personal_info.username": new RegExp(query, "i") })
        .limit(50)
        .select("personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .then(users => {
            return res.status(200).json({ users });
        })
        .catch((err) => {
            return res.status(500).json({ error: err.message });
        });

});




server.post("/create-blog", verifyJWT, async (req, res) => {
    try {
        let authorId = req.user;
        let { title, description, tags, banner, content, draft } = req.body;
        if (!title || title.trim().length === 0) {
            return res.status(400).json({ error: "Title is required" });
        }

        if (!draft) {

            if (!description || description.trim().length === 0 || description.length > 200) {
                return res.status(400).json({ error: "Description is required and must be less than 200 characters" });
            }

            if (!banner || banner.trim().length === 0) {
                return res.status(400).json({ error: "Banner is required" });
            }

            if (!tags || !Array.isArray(tags) || tags.length === 0 || tags.length > 10) {
                return res.status(400).json({ error: "Tags are required and must be less than 10" });
            }
        }

        tags = tags.map(tag => tag.toLowerCase());
        let blog_id = title.replace(/[^a-zA-Z0-9]/g, "").replace(/\s/g, "-").trim() + nanoid(5);
        let blog = new Blog({
            title,
            des: description,
            tags,
            banner,
            content,
            author: authorId,
            blog_id,
            draft: Boolean(draft)
        });

        let savedBlog = await blog.save();

        let incrementVal = draft ? 0 : 1;
        await User.findOneAndUpdate({ _id: authorId }, {
            $inc: { "account_info.total_posts": incrementVal },
            $push: { "blogs": savedBlog._id }
        });

        return res.status(200).json({ id: savedBlog.blog_id });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ "error": "Failed to create blog", details: error.message });
    }
});

server.post("/like-blog", verifyJWT, async (req, res) => {

    let user_id = req.user;

    let { _id, islikedByUser } = req.body;

    let incrementalVal = !islikedByUser ? 1 : -1;

    Blog.findOneAndUpdate({ _id }, {
        $inc: { "activity.total_likes": incrementalVal },
    })
        .then(blog => {
            if (!islikedByUser) {
                let like = new Notification({
                    blog: _id,
                    type: "like",
                    notification_for: blog.author,
                    user: user_id
                });
                like.save()
                    .then(() => {
                        return res.status(200).json({ liked_by_user: true });
                    })
            }
            else {
                Notification.findOneAndDelete({ blog: _id, type: "like", user: user_id })
                    .then(data => {
                        return res.status(200).json({ liked_by_user: false });
                    })
                    .catch(err => {
                        return res.status(500).json({ error: err.message });
                    });
            }
        })


});


server.post("/isliked-by-user", verifyJWT, async (req, res) => {
    let user_id = req.user;

    let { _id } = req.body;

    Notification.exists({ blog: _id, type: "like", user: user_id })
        .then(result => {
            return res.status(200).json({ result })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });


});


server.get("/get-comments/:blogId", async (req, res) => {
    try {
        const blogId = req.params.blogId;
        const comments = await Comment.find({ blog_id: blogId });
        res.status(200).json(comments);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});





server.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});
