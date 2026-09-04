function DashboardSkeleton() {

    return (

        <div className="space-y-6 animate-pulse">

            <div className="flex justify-between">

                <div>

                    <div className="h-8 w-64 bg-slate-700 rounded"></div>

                    <div className="h-4 w-96 bg-slate-700 rounded mt-3"></div>

                </div>

                <div className="h-10 w-40 bg-slate-700 rounded"></div>

            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-6">

                {[1,2,3,4].map((i)=>(

                    <div
                        key={i}
                        className="h-36 rounded-xl bg-slate-800 border border-slate-700"
                    />

                ))}

            </div>

            <div className="grid grid-cols-3 gap-6">

                <div className="col-span-2 h-72 rounded-xl bg-slate-800 border border-slate-700"></div>

                <div className="h-72 rounded-xl bg-slate-800 border border-slate-700"></div>

            </div>

            <div className="h-96 rounded-xl bg-slate-800 border border-slate-700"></div>

        </div>

    );

}

export default DashboardSkeleton;