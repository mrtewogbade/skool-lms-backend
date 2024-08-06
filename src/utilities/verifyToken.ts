import express, { Request, Response } from "express";
import { User } from "../entity/user";
import { AppDataSource } from "../database/data-source";
import jwt from "jsonwebtoken";

const secret: string = process.env.JWT_SECRET ?? "";

export async function checkAndVerifyToken(
  req: Request,
  res: Response
): Promise<Response | undefined> {
  try {
    const userRepository = AppDataSource.getRepository(User);
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res
        .status(401)
        .json({ error: "Unauthorized - Token not provided" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, secret) as { id: string };
    } catch (error: any) {
      if (error.name === "TokenExpiredError") {
        return res
          .status(401)
          .json({ error: "Unauthorized - Token has expired" });
      } else {
        return res
          .status(401)
          .json({ error: "Unauthorized - Token verification failed" });
      }
    }

    const userInfo = await userRepository.findOne({
      where: { id: decoded.id },
    });

    if (userInfo) {
      const user = {
        firstName: userInfo.firstName,
        lastName: userInfo.lastName,
        email: userInfo.email,
        phone: userInfo.phoneNumber,
        country: userInfo.countryOfResidence,
        userId: userInfo.id,
      };

      res.json({ user });
    } else {
      return res.status(401).json({ error: "Unauthorized - User not found" });
    }
  } catch (error: any) {
    console.error("Error verifying token:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}
