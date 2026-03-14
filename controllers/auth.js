const bcrypt = require("bcrypt");

exports.changePassword = async function (req, res) {

    try {

        let user = req.user;

        const { oldPassword, newPassword } = req.body;

        if (!oldPassword || !newPassword) {
            return res.status(400).send("Thiếu password");
        }

        if (newPassword.length < 8) {
            return res.status(400).send("Password phải >= 8 ký tự");
        }

        let check = await bcrypt.compare(oldPassword, user.password);

        if (!check) {
            return res.status(400).send("Old password không đúng");
        }

        let hash = await bcrypt.hash(newPassword, 10);

        user.password = hash;

        await user.save();

        res.send({ message: "Đổi mật khẩu thành công" });

    } catch (error) {

        res.status(500).send(error.message);

    }

}