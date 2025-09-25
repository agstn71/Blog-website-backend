import { User } from "../models/user.model.js";
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import getDataUri from "../utils/dataUri.js";
import cloudinary from "../utils/cloudinary.js";
import crypto from "crypto";
import nodemailer from "nodemailer";
import { Blog } from "../models/blog.model.js";


export const register = async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;
        if (!firstName || !lastName || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            })
        }
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: "Invalid email"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: "Password must be at least 6 characters"
            });
        }

        const existingUserByEmail = await User.findOne({ email: email });

        if (existingUserByEmail) {
            return res.status(400).json({ success: false, message: "Email already exists" });
        }

        // const existingUserByUsername = await User.findOne({ userName: userName });

        // if (existingUserByUsername) {
        //     return res.status(400).json({ success: false, message: "Username already exists" });
        // }

        const hashedPassword = await bcrypt.hash(password, 10);

        await User.create({
            firstName,
            lastName,
            email,
            password: hashedPassword
        })

        return res.status(201).json({
            success: true,
            message: "Account Created Successfully"
        })

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Failed to register"
        })

    }
}

export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email && !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            })
        }

        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid email or password "
            })
        }

        const isPasswordValid = await bcrypt.compare(password, user.password)
        if (!isPasswordValid) {
            return res.status(400).json({
                success: false,
                message: "Invalid email or password"
            })
        }

        const token = jwt.sign(
            { userId: user._id },
            process.env.SECRET_KEY,
            { expiresIn: "1d" }
        );

        return res
            .status(200)
            .cookie("token", token, {
                httpOnly: true,       // ✅ correct
                secure: true,         // ✅ needed for HTTPS
                sameSite: "None",     // ✅ allow cross-origin (Vercel <-> Render)
                maxAge: 24 * 60 * 60 * 1000, // ✅ 1 day
                path: "/"             // ✅ available everywhere
            })
            .json({
                success: true,
                message: `Welcome back ${user.firstName}`,
                user,
            });

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Failed to Login",
        })
    }

}

export const logout = async (_, res) => {
    try {
        return res.status(200).cookie("token", "", { maxAge: 0 }).json({
            message: "Logged out successfully.",
            success: true
        })
    } catch (error) {
        console.log(error);
    }
}

export const updateProfile = async (req, res) => {
    try {
        const userId = req.user.id
        const { firstName, lastName, occupation, bio, instagram, facebook, linkedin, github } = req.body;
        const file = req.file;

        let cloudResponse
        if(file) {
            const fileUri = getDataUri(file)
         cloudResponse = await cloudinary.uploader.upload(fileUri)
        }

       

        const user = await User.findById(userId).select("-password")

        if (!user) {
            return res.status(404).json({
                message: "User not found",
                success: false
            })
        }

        // updating data
        if (firstName) user.firstName = firstName
        if (lastName) user.lastName = lastName
        if (occupation) user.occupation = occupation
        if (instagram) user.instagram = instagram
        if (facebook) user.facebook = facebook
        if (linkedin) user.linkedin = linkedin
        if (github) user.github = github
        if (bio) user.bio = bio
        if (file) user.photoUrl = cloudResponse.secure_url

        await user.save()
        return res.status(200).json({
            message: "profile updated successfully",
            success: true,
            user
        })

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Failed to update profile"
        })
    }
}

export const getAllUsers = async (req, res) => {
    try {
        const users = await User.find().select('-password'); // exclude password field
        res.status(200).json({
            success: true,
            message: "User list fetched successfully",
            total: users.length,
            users
        });
    } catch (error) {
        console.error("Error fetching user list:", error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch users"
        });
    }
};

export const forgotPassword = async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (user) {
        // Generate token only if user exists
        const resetToken = crypto.randomBytes(32).toString("hex");
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpire = Date.now() + 3600000; // 1 hour
        await user.save();

        const resetUrl = `https://blog-agstn.vercel.app/reset-password/${resetToken}`;

        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Password Reset Request",
            html: `<p>Click this link to reset your password:</p>
                   <a href="${resetUrl}">${resetUrl}</a>
                   <p>This link will expire in 1 hour.</p>`,
        };

        try {
            await transporter.sendMail(mailOptions);
        } catch (err) {
            // If email fails, remove token
            user.resetPasswordToken = undefined;
            user.resetPasswordExpire = undefined;
            await user.save();
            console.error(err);
        }
    }

    // Always return this message, regardless of whether user exists
    res.status(200).json({
        message: "If an account with that email exists, a password reset link has been sent."
    });
};


export const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    // 1. Find user with valid token
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpire: { $gt: Date.now() }, // token still valid
    });

    if (!user) {
      return res.status(400).json({ success: false, message: "Invalid or expired token" });
    }

    // 2. Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Update user password
    user.password = hashedPassword;
    user.resetPasswordToken = undefined; // clear token
    user.resetPasswordExpire = undefined; // clear expiry
    await user.save();

    return res.status(200).json({
      success: true,
      message: "Password has been reset successfully. You can now login.",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

export const deleteAccount = async(req,res) => {
    console.log("inside deleteACcount")
  try {
    const userId = req.user.id
    await Blog.deleteMany({author:userId})
    await User.findByIdAndDelete(userId)


       res.cookie("token", "", {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      expires: new Date(0), // set cookie expiration to past
      path: "/",
    });

    res.status(200).json({success:true,message:"Account deleted successfully"})
  } catch (error) {
    res.status(500).json({success:false, message:"Failed to delete account"})
  }
    
}