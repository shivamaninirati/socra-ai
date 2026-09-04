function Button({

    children,

    onClick,

    color = "cyan",

    disabled = false

}) {

    const colors = {

        cyan: "bg-cyan-600 hover:bg-cyan-500",

        green: "bg-green-600 hover:bg-green-500",

        red: "bg-red-600 hover:bg-red-500",

        orange: "bg-orange-600 hover:bg-orange-500"

    };

    return (

        <button

            onClick={onClick}

            disabled={disabled}

            className={`

                px-5

                py-3

                rounded-lg

                font-medium

                transition

                ${colors[color]}

                disabled:opacity-50

            `}
        >

            {children}

        </button>

    );

}

export default Button;