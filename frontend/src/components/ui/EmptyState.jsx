import { ShieldAlert } from "lucide-react";

function EmptyState({

    title,

    description

}) {

    return (

        <div
            className="
                bg-slate-800
                border
                border-dashed
                border-slate-600
                rounded-2xl
                p-14
                text-center
            "
        >

            <div
                className="
                    w-20
                    h-20
                    mx-auto
                    rounded-full
                    bg-slate-700
                    flex
                    items-center
                    justify-center
                    mb-6
                "
            >

                <ShieldAlert
                    size={36}
                    className="text-cyan-400"
                />

            </div>

            <h2 className="text-2xl font-bold text-white">

                {title}

            </h2>

            <p className="text-slate-400 mt-3 max-w-md mx-auto leading-7">

                {description}

            </p>

        </div>

    );

}

export default EmptyState;