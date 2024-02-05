const express=require("express")
const { fetchLawyer } = require("../controller/fetchLawyerController")
const router=express.Router()


router.route("/fetch").get(fetchLawyer)
// router.route("/login").post(loginUser)
// router.route("/login").get(logout)
// router.route("/password/forgot").post(forgotpassword)
// router.route("/password/reset/:token").put(resetpassword)

module.exports = router