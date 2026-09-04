import SeverityBadge from "./SeverityBadge";

function HuntResultsTable({ results }) {

    if (!results.length) {

        return (

            <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-10 text-center text-slate-500">

                No hunt results.

            </div>

        );

    }

    return (

        <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">

            <table className="w-full">

                <thead className="bg-slate-800/60">

                    <tr>

                        <th className="p-4 text-left">

                            Time

                        </th>

                        <th className="p-4 text-left">

                            Host

                        </th>

                        <th className="p-4 text-left">

                            Event

                        </th>

                        <th className="p-4 text-left">

                            Severity

                        </th>

                    </tr>

                </thead>

                <tbody>

                    {results.map((log, index) => (

                        <tr

                            key={index}

                            className="border-t border-slate-700/60 hover:bg-slate-900/40 transition-colors duration-100"

                        >

                            <td className="p-4">

                                {new Date(log.event.time).toLocaleString()}

                            </td>

                            <td className="p-4">

                                {log.event.host}

                            </td>

                            <td className="p-4">

                                {log.event.process_name}

                            </td>

                            <td className="p-4">

                                <SeverityBadge

                                    severity={log.detection.severity}

                                />

                            </td>

                        </tr>

                    ))}

                </tbody>

            </table>

        </div>

    );

}

export default HuntResultsTable;