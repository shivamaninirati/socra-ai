function Card({ title, children }) {

    return (

        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">

            {title && (

                <h2 className="text-xl font-semibold mb-5 text-white">

                    {title}

                </h2>

            )}

            {children}

        </div>

    );

}

export default Card;