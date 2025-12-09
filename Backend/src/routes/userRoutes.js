import express from "express";
import { createUser, getUser, getUsers, deleteUser } from "../controllers/userController.js";

const router = express.Router();

router.post("/users", createUser);

router.get("/users", getUsers);

router.get("/users/:id", getUser);

router.delete("/users/:id", deleteUser);

export default router;