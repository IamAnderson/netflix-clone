import NextAuth from "next-auth"
import Credentials from "next-auth/providers/credentials"
import { compare } from "bcrypt"

import GithubProvider from "next-auth/providers/github"
import GoogleProvider from "next-auth/providers/google"

import { PrismaAdapter } from "@next-auth/prisma-adapter"

import prismadb from "../../../libs/prismadb"

export default NextAuth({
  providers: [
    GithubProvider({
      clientId: process.env.GITHUB_ID || "b6988cdf4094d5247201",
      clientSecret: process.env.GITHUB_SECRET || "d678c7912c5c93024405d3846f2b7dcd7bd1b3dd"
    }),
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID || "578631044047-gjl35konse4c41tn3171mq29hnkoh6os.apps.googleusercontent.com",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "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"
    }),
    Credentials({
      id: "credentials",
      name: "Credentials",
      credentials: {
        email: {
          label: "Email",
          type: "text",
        },
        paswword: {
          labe: "Password",
          type: "password",
        },
      },

      async authorize(credentials) {
        if (!credentials?.email || !credentials?.paswword) {
          throw new Error("Email and password required")
        }

        const user = await prismadb?.user.findUnique({
          where: {
            email: credentials?.email,
          },
        })

        if (!user || !user?.hashedPassword) {
          throw new Error("Email does not exist")
        }

        const isCorrectPassword = await compare(
          credentials?.paswword,
          user?.hashedPassword
        )

        if (!isCorrectPassword) {
          throw new Error("Incorrect Password")
        }

        return user;
      },
    }),
  ],
  pages: {
    signIn: "/auth",
  },
  debug: process.env.NODE_ENV === "development",
  adapter: PrismaAdapter(prismadb),
  session: {
    strategy: "jwt",
  },
  jwt: {
    secret: process.env.NEXTAUTH_JWT_SECRET,
  },
  secret: process.env.NEXTAUTH_SECRET,
})