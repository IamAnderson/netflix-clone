import React from 'react'

interface InputProps {
    id: string;
    onChange: React.ChangeEventHandler<HTMLInputElement>;
    label: string;
    value: string;
    type: string;
}

const Input = ({ id, label, onChange, type, value }: InputProps) => {
    return (
        <div className='relative'>
            <input
                id={id}
                type={type}
                value={value}
                onChange={onChange}
                className='rounded-md px-6 pt-6 pb-1 w-full text-md text-white bg-neutral-700 appearance-none focus:outline-none'

                placeholder=' '
            />

            <label htmlFor={id}
                className='
    absolute
    text-md text-zinc-400
    duration-150
    transform
    -translate-y-3
    scale-75
    top-4
    z-10
    origin-[0]
    left-6
    peer-placeholder-shown:scale-100
    peer-placeholder-shown:translate-y-0
    peer-focus:scale-75
    peer-focus:-translate-y-3
    '
            >
                {label}
            </label>
        </div>
    )
}

export default Input