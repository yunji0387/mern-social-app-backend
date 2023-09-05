import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

// register user
export const register = async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            email,
            password,
            picturePath,
            location
        } = req.body;

        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = new User({
            firstName,
            lastName,
            email,
            password: passwordHash,
            picturePath,
            location
        });
        const savedUser = await newUser.save();
        res.status(201).json(savedUser); //indicate user register successfully
    }catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Logging in
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email });
        if(!user) return res.status(400).json({ msg: "User does not exists." });

        const isMatch = await bcrypt.compare(password, user.password);

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        delete user.password; //make sure it does not send back to front end
        res.status(200).json({ token, user });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}