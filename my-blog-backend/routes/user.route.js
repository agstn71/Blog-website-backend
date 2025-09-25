import express from "express"
import { getAllUsers, login, logout, register, updateProfile,forgotPassword, resetPassword, deleteAccount } from "../controllers/user.controller.js"
import { isAuthenticated } from "../middleware/isAuthenticated.js"
import { singleUpload } from "../middleware/multer.js"

const router = express.Router()

router.route("/register").post(register)
router.route("/login").post(login)
router.route("/logout").get(logout)
router.route("/profile/update").put(isAuthenticated, singleUpload, updateProfile)
router.get('/all-users', getAllUsers);
router.route("/forgot-password").post(forgotPassword)
router.route("/reset-password/:token").post(resetPassword)
router.route("/delete-account").delete(isAuthenticated,deleteAccount)

export default router;