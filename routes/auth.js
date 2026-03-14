let express = require('express')
let router = express.Router()

let userController = require('../controllers/users')
let { RegisterValidator, validatedResult } = require('../utils/validator')

let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let fs = require("fs")

const privateKey = fs.readFileSync("./private.key")

const { checkLogin } = require('../utils/authHandler')


// REGISTER
router.post('/register', RegisterValidator, validatedResult, async function (req, res) {

    let { username, password, email } = req.body;

    let hashPassword = bcrypt.hashSync(password, 10)

    let newUser = await userController.CreateAnUser(
        username,
        hashPassword,
        email,
        '69b2763ce64fe93ca6985b56',
        null,
        null,
        true,
        0
    )

    res.send(newUser)
})


// LOGIN
router.post('/login', async function (req, res) {

    let { username, password } = req.body;

    let user = await userController.FindUserByUsername(username);

    if (!user) {
        return res.status(404).send({
            message: "thong tin dang nhap khong dung"
        })
    }

    if (!user.lockTime || user.lockTime < Date.now()) {

        if (bcrypt.compareSync(password, user.password)) {

            user.loginCount = 0
            await user.save()

            let token = jwt.sign(
                { id: user._id },
                privateKey,
                {
                    algorithm: "RS256",
                    expiresIn: "1h"
                }
            )

            return res.send({
                token: token
            })

        } else {

            user.loginCount = (user.loginCount || 0) + 1

            if (user.loginCount == 3) {
                user.loginCount = 0
                user.lockTime = new Date(Date.now() + 60 * 60 * 1000)
            }

            await user.save()

            return res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
        }

    } else {

        return res.status(404).send({
            message: "user dang bi ban"
        })
    }

})


// CHANGE PASSWORD
router.post("/changepassword", checkLogin, async function (req, res) {

    try {

        let user = req.user

        let { oldPassword, newPassword } = req.body

        if (!oldPassword || !newPassword) {
            return res.status(400).send({
                message: "thieu password"
            })
        }

        if (newPassword.length < 8) {
            return res.status(400).send({
                message: "password phai >= 8 ky tu"
            })
        }

        let check = bcrypt.compareSync(oldPassword, user.password)

        if (!check) {
            return res.status(400).send({
                message: "old password khong dung"
            })
        }

        let hash = bcrypt.hashSync(newPassword, 10)

        user.password = hash

        await user.save()

        res.send({
            message: "doi mat khau thanh cong"
        })

    } catch (error) {

        res.status(500).send(error.message)

    }

})


// ME
router.get('/me', checkLogin, function (req, res) {
    res.send(req.user)
})

module.exports = router