let jwt = require('jsonwebtoken')
let fs = require("fs")

let userController = require("../controllers/users")

const publicKey = fs.readFileSync("./public.key")

module.exports = {

    checkLogin: async function (req, res, next) {

        try {

            let token = req.headers.authorization

            if (!token || !token.startsWith("Bearer")) {
                return res.status(401).send("ban chua dang nhap")
            }

            token = token.split(" ")[1]

            let result = jwt.verify(token, publicKey, {
                algorithms: ["RS256"]
            })

            let user = await userController.FindUserById(result.id)

            if (!user) {
                return res.status(401).send("user khong ton tai")
            }

            req.user = user

            next()

        } catch (error) {

            res.status(401).send("token khong hop le")

        }

    }

}