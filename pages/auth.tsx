import Input from '../components/Input'
import React from 'react'
import axios from "axios"
import { signIn } from "next-auth/react"
import { useRouter } from 'next/navigation'
import { FcGoogle } from "react-icons/fc"
import { FaGithub } from "react-icons/fa"

const Auth = () => {
    const router = useRouter();

    const [email, setEmail] = React.useState("");
    const [name, setName] = React.useState("");
    const [password, setPassword] = React.useState("");

    const [variant, setVariant] = React.useState("login");
    const toggleVariant = React.useCallback(() => {
        setVariant((currentVariant) => (currentVariant === "login" ? "register" : "login"))
    }, []);


    const register = React.useCallback(async () => {
        try {
            await axios.post("/api/auth/register", {
                email,
                name,
                password
            });

            login();
        } catch (error) {
            console.log(error)
        }
    }, [email, name, password]);

    const login = React.useCallback(async () => {
        try {
            await signIn("credentials", {
                email,
                password,
                redirect: false,
                callbackUrl: "/"
            });

            router.push("/")
        } catch (error) {
            console.log(error)
        }
    }, [email, password]);

    return (
        <div className='relative h-screen w-full bg-[url("/images/hero.jpg")] bg-no-repeat bg-center bg-fixed bg-cover'>
            <div className='bg-black w-full h-full lg:bg-opacity-50'>
                <nav className='px-12 py-5'>
                    <img src="/images/logo.png" alt="" className='h-12 object-contain' />
                </nav>
                <div className='flex justify-center'>
                    <div className='bg-black bg-opacity-70 p-16 self-center mt-2 lg:w-2/5 lg:max-w-md rounded-md w-full'>
                        <h2 className='text-white text-4xl mb-8 font-semibold'>
                            {variant === "login" ? "Sign in" : "Register"}
                        </h2>
                        <div className='flex flex-col gap-4'>
                            {variant === "register" && (
                                <Input
                                    id='name'
                                    onChange={(e) => setName(e.target.value)}
                                    label='Username'
                                    type='string'
                                    value={name}
                                />
                            )}

                            <Input
                                id='email'
                                onChange={(e) => setEmail(e.target.value)}
                                label='Email'
                                type='email'
                                value={email}
                            />

                            <Input
                                id='password'
                                onChange={(e) => setPassword(e.target.value)}
                                label='Password'
                                type='password'
                                value={password}
                            />
                        </div>
                        <button className='bg-red-600 py-3 text-white rounded-md w-full mt-10 hover:bg-red-700 transition'
                            onClick={variant === "login" ? login : register}
                        >
                            {variant === "login" ? "Login" : "Sign Up"}
                        </button>
                        <div className='flex flex-row items-center gap-4 mt-8 justify-center'>
                            <div
                                onClick={() => signIn("google", { callbackUrl: "/" })}
                                className='
                            w-10 h-10
                            bg-white
                            rounded-full
                            flex items-center justify-center
                            cursor-pointer
                            hover:opacity-80
                            transition
                            '>
                                <FcGoogle size={30} />
                            </div>
                            <div
                                onClick={() => signIn("github", { callbackUrl: "/" })}
                                className='
                            w-10 h-10
                            bg-white
                            rounded-full
                            flex items-center justify-center
                            cursor-pointer
                            hover:opacity-80
                            transition
                            '>
                                <FaGithub size={30} />
                            </div>
                        </div>
                        <p className='text-neutral-500 mt-12'>
                            {variant === "login" ? (
                                "First time using Netflix?"
                            ) : "Already have an account?"}
                            <span onClick={toggleVariant} className='text-white ml-1 hover:underline cursor-pointer'>
                                {variant === "login" ? (
                                    "Create an account"
                                ) : "Login"}
                            </span>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default Auth