import { Component } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

/**
 * Error boundary that isolates search result rendering errors.
 * A crash inside search results shows "Unable to display search results"
 * instead of taking down the entire application shell.
 */
class SearchErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("[SearchErrorBoundary] Search rendering error:", error, errorInfo);
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center py-20">
          <div className="w-14 h-14 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center mb-4">
            <AlertTriangle size={24} className="text-red-400" />
          </div>
          <p className="text-sm font-bold text-red-400">Unable to display search results</p>
          <p className="text-xs text-slate-500 mt-1.5 max-w-sm text-center">
            A rendering error occurred while displaying results. The rest of the application is unaffected.
          </p>
          <button
            onClick={this.handleRetry}
            className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-cyan-500/40 hover:text-white"
          >
            <RefreshCw size={12} /> Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default SearchErrorBoundary;
