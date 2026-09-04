import { useState, useEffect, useRef, useCallback } from "react";
import {
  Bot, Shield, Search, Terminal, FileWarning, Brain, Send,
  Plus, MessageSquare, Trash2, Pencil, X, StopCircle,
  RotateCcw, Loader2, MessageCircle, MoreVertical,
} from "lucide-react";
import api from "../services/api";
import PageHeader from "../components/ui/PageHeader";

/* ── Relative time helper ─────────────────────────────────────────── */
function relativeTime(dateStr) {
  if (!dateStr) return "";
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  if (isNaN(then)) return "";
  const diff = now - then;
  if (diff < 0) return "Just now";
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return "Just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min} min ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day === 1) return "Yesterday";
  if (day < 7) return `${day}d ago`;
  const week = Math.floor(day / 7);
  if (week < 4) return `${week}w ago`;
  return new Date(dateStr).toLocaleDateString("en-GB", { day: "numeric", month: "short" });
}

/* ── Component ────────────────────────────────────────────────────── */
function AIChat() {
  const [question, setQuestion] = useState("");
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState([]);
  const [currentConversationId, setCurrentConversationId] = useState(null);
  const [conversations, setConversations] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [activeMenuId, setActiveMenuId] = useState(null);
  const [renamingId, setRenamingId] = useState(null);
  const [renameValue, setRenameValue] = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState(null);
  const [deleteAllConfirm, setDeleteAllConfirm] = useState(false);
  const [abortController, setAbortController] = useState(null);
  const [tick, setTick] = useState(0); // forces re-render for live timestamps
  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);
  const sidebarRef = useRef(null);
  const menuRefs = useRef({});

  const STORAGE_KEY = "socra_ai_selected_conversation";

  /* ── Live timestamp updater — re-render every 30s ──────────── */
  useEffect(() => {
    const interval = setInterval(() => setTick((t) => t + 1), 30000);
    return () => clearInterval(interval);
  }, []);

  /* ── Scroll to bottom ─────────────────────────────────────────── */
  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);
  useEffect(() => { scrollToBottom(); }, [messages, loading, scrollToBottom]);

  /* ── Load conversations on mount ─────────────────────────────── */
  useEffect(() => { initializeChat(); }, []);

  /* ── Close menus on outside click ────────────────────────────── */
  useEffect(() => {
    const handler = (e) => {
      if (activeMenuId && sidebarRef.current && !sidebarRef.current.contains(e.target)) {
        setActiveMenuId(null);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [activeMenuId]);

  /* ── Initialize: load list + restore selected conversation ───── */
  const initializeChat = async () => {
    setLoadingHistory(true);
    setLoadError(null);
    try {
      const resp = await api.get("/ai/conversations");
      if (!resp.data?.success) {
        setLoadError("Unable to load conversation history.");
        setLoadingHistory(false);
        return;
      }
      const convs = resp.data.conversations || [];
      setConversations(convs);

      const savedId = localStorage.getItem(STORAGE_KEY);
      const targetId = savedId && convs.find((c) => c.id === savedId)
        ? savedId
        : convs.length > 0 ? convs[0].id : null;

      if (targetId) {
        await loadConversationMessages(targetId);
      } else {
        setCurrentConversationId(null);
        setMessages([]);
      }
    } catch (error) {
      console.error("Failed to initialize chat:", error);
      setLoadError("Unable to load conversation history.");
    } finally {
      setLoadingHistory(false);
    }
  };

  /* ── Refresh conversation list WITHOUT changing selected conv ── */
  const refreshConversationList = async () => {
    try {
      const resp = await api.get("/ai/conversations");
      if (resp.data?.success) {
        setConversations(resp.data.conversations || []);
      }
    } catch (error) {
      console.error("Failed to refresh conversations:", error);
    }
  };

  /* ── Load messages for a specific conversation ──────────────── */
  const loadConversationMessages = async (conversationId) => {
    try {
      const resp = await api.get(`/ai/conversations/${conversationId}`);
      if (resp.data?.success) {
        setMessages(resp.data.messages || []);
        setCurrentConversationId(conversationId);
        localStorage.setItem(STORAGE_KEY, conversationId);
        setLoadError(null);
      } else {
        setLoadError("Unable to load conversation.");
      }
    } catch (error) {
      console.error("Failed to load conversation:", error);
      setLoadError("Unable to load conversation.");
    }
  };

  /* ── Click a conversation from the list ─────────────────────── */
  const selectConversation = async (conversationId) => {
    if (conversationId === currentConversationId) return;
    setActiveMenuId(null);
    await loadConversationMessages(conversationId);
  };

  /* ── Create new conversation ─────────────────────────────────── */
  const createNewConversation = async () => {
    try {
      const resp = await api.post("/ai/conversations/new", { title: "New Investigation" });
      if (resp.data?.success) {
        const newConv = resp.data.conversation;
        newConv.message_count = 0;
        newConv.last_message_content = "";
        setConversations((prev) => [newConv, ...prev]);
        setMessages([]);
        setCurrentConversationId(newConv.id);
        localStorage.setItem(STORAGE_KEY, newConv.id);
        textareaRef.current?.focus();
      }
    } catch (error) {
      console.error("Failed to create new conversation:", error);
    }
  };

  /* ── Send message to AI ──────────────────────────────────────── */
  const askAI = async (text = question) => {
    if (!text.trim() || loading) return;
    const userMessage = text.trim();
    setQuestion("");
    setLoading(true);

    // Immediately show user message in UI
    const userMsg = { role: "user", content: userMessage, time: new Date().toISOString() };
    setMessages((prev) => [...prev, userMsg]);

    const controller = new AbortController();
    setAbortController(controller);

    try {
      const resp = await api.post(
        "/ai/chat",
        { question: userMessage, conversation_id: currentConversationId },
        { signal: controller.signal }
      );
      const data = resp.data || {};

      if (data.conversation_id) {
        if (data.conversation_id !== currentConversationId) {
          setCurrentConversationId(data.conversation_id);
          localStorage.setItem(STORAGE_KEY, data.conversation_id);
        }
        // Reload full conversation from DB (includes both user + assistant messages)
        await loadConversationMessages(data.conversation_id);
        // Refresh the sidebar list to show updated title/preview
        await refreshConversationList();
      }
    } catch (error) {
      if (error.name === "CanceledError" || error.name === "AbortError") {
        return;
      }
      // Error occurred — keep user message, show error as assistant message
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Unable to generate a response. Please try again.",
          time: new Date().toISOString(),
          status: "failed",
        },
      ]);
    } finally {
      setLoading(false);
      setAbortController(null);
    }
  };

  /* ── Stop generation ─────────────────────────────────────────── */
  const stopGeneration = () => {
    if (abortController) abortController.abort();
    setLoading(false);
    setAbortController(null);
  };

  /* ── Delete conversation ─────────────────────────────────────── */
  const deleteConversation = async (convId) => {
    try {
      await api.delete(`/ai/conversations/${convId}`);
      setConversations((prev) => prev.filter((c) => c.id !== convId));
      if (currentConversationId === convId) {
        const remaining = conversations.filter((c) => c.id !== convId);
        if (remaining.length > 0) await loadConversationMessages(remaining[0].id);
        else {
          setCurrentConversationId(null);
          setMessages([]);
          localStorage.removeItem(STORAGE_KEY);
        }
      }
    } catch (error) {
      console.error("Failed to delete conversation:", error);
    }
    setDeleteConfirm(null);
    setActiveMenuId(null);
  };

  /* ── Delete all conversations ────────────────────────────────── */
  const deleteAllConversations = async () => {
    try {
      await api.delete("/ai/conversations");
      setConversations([]);
      setCurrentConversationId(null);
      setMessages([]);
      localStorage.removeItem(STORAGE_KEY);
    } catch (error) {
      console.error("Failed to delete all conversations:", error);
    }
    setDeleteAllConfirm(false);
  };

  /* ── Rename conversation ─────────────────────────────────────── */
  const renameConversation = async (convId) => {
    if (!renameValue.trim()) { setRenamingId(null); return; }
    try {
      await api.patch(`/ai/conversations/${convId}`, { title: renameValue.trim() });
      setConversations((prev) => prev.map((c) => c.id === convId ? { ...c, title: renameValue.trim() } : c));
    } catch (error) {
      console.error("Failed to rename conversation:", error);
    }
    setRenamingId(null);
    setActiveMenuId(null);
  };

  /* ── Start rename ────────────────────────────────────────────── */
  const startRename = (convId) => {
    const conv = conversations.find((c) => c.id === convId);
    setRenamingId(convId);
    setRenameValue(conv?.title || "");
    setActiveMenuId(null);
  };

  /* ── Search conversations ────────────────────────────────────── */
  const handleSearch = async (query) => {
    setSearchQuery(query);
    if (!query.trim()) { setSearchResults(null); return; }
    try {
      const resp = await api.post("/ai/conversations/search", { query });
      if (resp.data?.success) setSearchResults(resp.data.conversations || []);
    } catch (error) {
      console.error("Failed to search conversations:", error);
    }
  };

  const displayConversations = searchResults !== null ? searchResults : conversations;

  /* ── Render ──────────────────────────────────────────────────── */
  return (
    <div className="w-full pb-6 space-y-6 select-none">
      <div className="flex justify-between items-center border-none m-0 pt-6">
        <PageHeader title="SOCRA AI Copilot" subtitle="Enterprise AI assistant for investigations, threat hunting, MITRE ATT&CK, Windows events and incident response." />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-4 mt-6">
        {/* ── Left sidebar ──────────────────────────────────────── */}
        <div ref={sidebarRef} className="hidden xl:flex flex-col gap-4 h-[calc(100vh-14rem)]">
          {/* AI Modules card */}
          <div className="bg-slate-900/20 border border-slate-800/80 rounded-xl p-4 shadow-sm backdrop-blur-sm">
            <h2 className="text-xs font-bold uppercase tracking-wider mb-3 text-white">AI Modules</h2>
            <div className="space-y-2.5">
              <div className="flex items-center gap-2.5 text-xs font-semibold text-slate-300"><Shield size={14} className="text-cyan-400 shrink-0" /><span>Investigation Engine</span></div>
              <div className="flex items-center gap-2.5 text-xs font-semibold text-slate-300"><Brain size={14} className="text-cyan-400 shrink-0" /><span>MITRE ATT&CK Matrix</span></div>
              <div className="flex items-center gap-2.5 text-xs font-semibold text-slate-300"><Search size={14} className="text-cyan-400 shrink-0" /><span>Threat Hunting Intel</span></div>
              <div className="flex items-center gap-2.5 text-xs font-semibold text-slate-300"><Terminal size={14} className="text-cyan-400 shrink-0" /><span>Windows Log Parser</span></div>
              <div className="flex items-center gap-2.5 text-xs font-semibold text-slate-300"><FileWarning size={14} className="text-cyan-400 shrink-0" /><span>Incident Response Flow</span></div>
            </div>
          </div>

          {/* Recent Chats panel */}
          <div className="flex-1 min-h-0 bg-slate-900/20 border border-slate-800/80 rounded-xl p-4 shadow-sm backdrop-blur-sm flex flex-col">
            {/* Header: New Chat + Delete All */}
            <div className="flex items-center gap-2 mb-3 shrink-0">
              <button onClick={createNewConversation} className="flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-cyan-600/20 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-600/30 hover:text-cyan-300 text-xs font-bold uppercase tracking-wider transition-all duration-150">
                <Plus size={14} /><span>New Chat</span>
              </button>
              {conversations.length > 0 && (
                <button onClick={() => setDeleteAllConfirm(true)} title="Delete all chats" className="flex items-center justify-center p-2 rounded-lg bg-slate-900/40 border border-slate-800/40 text-slate-500 hover:text-red-400 hover:border-red-500/30 transition-all duration-150">
                  <Trash2 size={14} />
                </button>
              )}
            </div>

            {/* Search */}
            <div className="relative mb-3 shrink-0">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => handleSearch(e.target.value)}
                placeholder="Search chats..."
                className="w-full pl-8 pr-3 py-2 rounded-lg bg-slate-900/40 border border-slate-800/40 text-xs text-slate-300 placeholder:text-slate-500 outline-none focus:border-cyan-500/50 transition-colors font-mono"
              />
              {searchQuery && (
                <button onClick={() => { setSearchQuery(""); setSearchResults(null); }} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                  <X size={12} />
                </button>
              )}
            </div>

            {/* Section label */}
            <h2 className="text-[10px] font-bold uppercase tracking-wider mb-2 text-slate-500 shrink-0">Recent Chats</h2>

            {/* Chat list */}
            <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: "none", msOverflowStyle: "none" }}>
              <style dangerouslySetInnerHTML={{ __html: `div::-webkit-scrollbar { display: none !important; width: 0 !important; }` }} />

              {displayConversations.length === 0 && !loadingHistory && (
                <div className="flex flex-col items-center justify-center py-8 text-center">
                  <MessageCircle size={24} className="text-slate-700 mb-2" />
                  <p className="text-[11px] font-semibold text-slate-500">No conversations yet</p>
                  <p className="text-[10px] text-slate-600 mt-1 max-w-[150px]">Start an investigation with the SOCRA AI Copilot.</p>
                </div>
              )}

              {displayConversations.map((conv) => {
                const isActive = currentConversationId === conv.id;
                const preview = conv.last_message_content || "";
                const truncatedPreview = preview.length > 35 ? preview.substring(0, 35) + "..." : preview;

                return (
                  <div key={conv.id} className="relative group">
                    {renamingId === conv.id ? (
                      /* ── Inline rename row ──────────────────────── */
                      <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-slate-900/60 border border-cyan-500/30">
                        <MessageSquare size={12} className="text-cyan-400 shrink-0" />
                        <input
                          autoFocus
                          value={renameValue}
                          onChange={(e) => setRenameValue(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") renameConversation(conv.id);
                            if (e.key === "Escape") setRenamingId(null);
                          }}
                          onBlur={() => renameConversation(conv.id)}
                          className="flex-1 bg-transparent border-none text-xs text-slate-200 outline-none font-mono"
                        />
                      </div>
                    ) : (
                      /* ── Conversation row ─────────────────────── */
                      <button
                        onClick={() => selectConversation(conv.id)}
                        className={`w-full text-left px-2.5 py-2 rounded-lg text-xs transition-all duration-100 flex items-center gap-2 ${
                          isActive
                            ? "bg-cyan-600/15 border border-cyan-500/25 text-cyan-300"
                            : "border border-transparent text-slate-400 hover:text-white hover:bg-slate-800/40 hover:border-slate-700/30"
                        }`}
                      >
                        <MessageSquare size={12} className="shrink-0 opacity-50" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="truncate font-semibold text-[11px] leading-tight">{conv.title || "New Investigation"}</span>
                          </div>
                          {truncatedPreview && (
                            <p className="text-[10px] text-slate-600 truncate leading-tight mt-0.5">{truncatedPreview}</p>
                          )}
                        </div>

                        {/* ⋮ Actions button */}
                        <div
                          className="shrink-0 relative"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <button
                            onClick={() => setActiveMenuId(activeMenuId === conv.id ? null : conv.id)}
                            className="p-1 rounded text-slate-600 hover:text-slate-300 hover:bg-slate-700/50 transition-colors"
                          >
                            <MoreVertical size={12} />
                          </button>
                          {activeMenuId === conv.id && (
                            <div className="absolute right-0 top-full mt-1 z-50 bg-slate-800 border border-slate-700 rounded-lg shadow-2xl shadow-black/50 py-1 min-w-[120px]">
                              <button
                                onClick={() => startRename(conv.id)}
                                className="w-full flex items-center gap-2 px-3 py-1.5 text-[11px] text-slate-300 hover:bg-slate-700/80 hover:text-white transition-colors"
                              >
                                <Pencil size={11} />Rename
                              </button>
                              <button
                                onClick={() => { setDeleteConfirm(conv.id); setActiveMenuId(null); }}
                                className="w-full flex items-center gap-2 px-3 py-1.5 text-[11px] text-red-400 hover:bg-red-500/10 hover:text-red-300 transition-colors"
                              >
                                <Trash2 size={11} />Delete
                              </button>
                            </div>
                          )}
                        </div>
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* ── Main conversation terminal ───────────────────────── */}
        <div className="xl:col-span-3 bg-slate-900/20 border border-slate-800/80 rounded-xl p-5 shadow-sm backdrop-blur-sm flex flex-col h-[calc(100vh-14rem)] relative">
          <div className="flex items-center justify-between pb-3 border-b border-slate-900/50 mb-4 shrink-0 z-10">
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider text-cyan-400">SOCRA AI Conversation Terminal</h2>
              <p className="text-[11px] text-slate-500 font-medium mt-0.5">Cryptographic session telemetry pipe initialized.</p>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={createNewConversation} className="xl:hidden flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600/20 border border-cyan-500/30 text-cyan-400 text-xs font-bold transition-all duration-150">
                <Plus size={13} /><span>New</span>
              </button>
              {currentConversationId && (
                <button
                  onClick={() => {
                    if (window.confirm("Clear all messages in this conversation?"))
                      api.post(`/ai/conversations/${currentConversationId}/clear`).then(() => {
                        setMessages([]);
                        refreshConversationList();
                      });
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900/40 border border-slate-800/80 text-slate-400 hover:text-red-400 text-xs font-bold transition-all duration-150"
                >
                  <Trash2 size={13} /><span>Clear</span>
                </button>
              )}
            </div>
          </div>

          {/* Messages area */}
          <div className="flex-1 overflow-y-auto space-y-4 pr-1 mb-4 z-10" style={{ scrollbarWidth: "none", msOverflowStyle: "none" }}>
            {messages.length === 0 && !loading && (
              <div className="h-full flex flex-col items-center justify-center text-xs font-medium text-slate-600 font-mono">
                <Bot size={40} className="text-slate-700 mb-3 animate-pulse" />
                <p>[ Waiting for remote model execution prompts... ]</p>
                <div className="mt-4 text-center max-w-md">
                  <p className="text-[10px] text-slate-600 leading-relaxed">Type a question below to begin an investigation.</p>
                </div>
              </div>
            )}

            {messages.map((msg, index) => (
              <div key={index} className={`flex w-full ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-[85%] rounded-xl px-4 py-2.5 text-xs leading-relaxed border select-text ${
                  msg.role === "user"
                    ? "bg-cyan-600/10 border-cyan-500/30 text-cyan-200 shadow-sm"
                    : "bg-slate-950/40 border-slate-800/80 text-slate-300"
                }`}>
                  <div className="flex items-center gap-2 mb-1.5 text-[10px] opacity-60 font-mono font-bold">
                    {msg.role === "assistant" ? <Bot size={12} className="text-cyan-400" /> : <Send size={11} className="text-cyan-400" />}
                    <span>{msg.role === "user" ? "ANALYST" : "SOCRA_CORE_AI"}</span>
                    <span>&bull;</span>
                    <span>{msg.time ? new Date(msg.time).toLocaleTimeString("en-GB", { hour12: false }) : ""}</span>
                    {msg.status === "failed" && <span className="text-red-400 ml-1">&bull; FAILED</span>}
                  </div>
                  <p className="whitespace-pre-wrap font-mono tracking-wide text-slate-200 selection:bg-cyan-500/20">
                    {msg.content}
                  </p>
                </div>
              </div>
            ))}

            {loading && (
              <div className="flex justify-start w-full">
                <div className="max-w-[85%] rounded-xl px-4 py-3 text-xs font-mono bg-slate-950/30 border border-slate-800/60 text-slate-500 flex items-center gap-2">
                  <Loader2 size={14} className="text-cyan-500/70 animate-spin" />
                  <span className="flex items-center gap-1">
                    <span className="animate-pulse">Generating response</span>
                    <span className="animate-pulse">...</span>
                  </span>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Error banner */}
          {loadError && (
            <div className="mb-3 px-4 py-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center justify-between">
              <span>{loadError}</span>
              <button onClick={() => { setLoadError(null); initializeChat(); }} className="flex items-center gap-1 px-2 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 text-[10px] font-bold">
                <RotateCcw size={10} />Retry
              </button>
            </div>
          )}

          {/* Input area */}
          <div className="pt-4 border-t border-slate-900/50 shrink-0 z-10">
            <div className="relative flex items-end bg-slate-950/40 border border-slate-800 rounded-xl overflow-hidden focus-within:border-cyan-500/50 transition-colors duration-150">
              <textarea
                ref={textareaRef}
                rows={2}
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    askAI();
                  }
                }}
                placeholder={loading ? "Generating response..." : "Message AI Assistant..."}
                disabled={loading}
                className="w-full bg-transparent text-xs p-3.5 pr-20 resize-none outline-none text-slate-200 placeholder:text-slate-500 font-mono disabled:opacity-50"
              />
              <div className="absolute right-2 bottom-2 shrink-0 flex items-center gap-1.5">
                {loading ? (
                  <button onClick={stopGeneration} className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-red-600/80 text-white hover:bg-red-500 text-xs font-bold transition-all duration-150 shadow-md">
                    <StopCircle size={13} /><span>Stop</span>
                  </button>
                ) : (
                  <button
                    disabled={!question.trim()}
                    onClick={() => askAI()}
                    className="flex items-center justify-center p-2 rounded-lg bg-cyan-600 text-white hover:bg-cyan-500 disabled:opacity-20 disabled:cursor-not-allowed transition-all duration-150 shadow-md"
                  >
                    <Send size={14} />
                  </button>
                )}
              </div>
            </div>
            <p className="text-[10px] text-slate-600 mt-2 font-mono text-center">Enter to send &bull; Shift+Enter for new line</p>
          </div>
        </div>
      </div>

      {/* ── Delete single confirmation ──────────────────────────── */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl p-6 shadow-2xl max-w-sm w-full mx-4">
            <h3 className="text-sm font-bold text-white mb-2">Delete this conversation?</h3>
            <p className="text-xs text-slate-400 mb-5">This action cannot be undone. All messages will be permanently deleted.</p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setDeleteConfirm(null)} className="px-4 py-2 rounded-lg bg-slate-800 border border-slate-700 text-xs font-bold text-slate-300 hover:bg-slate-700 transition-colors">Cancel</button>
              <button onClick={() => deleteConversation(deleteConfirm)} className="px-4 py-2 rounded-lg bg-red-600 text-xs font-bold text-white hover:bg-red-500 transition-colors">Delete</button>
            </div>
          </div>
        </div>
      )}

      {/* ── Delete all confirmation ─────────────────────────────── */}
      {deleteAllConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl p-6 shadow-2xl max-w-sm w-full mx-4">
            <h3 className="text-sm font-bold text-white mb-2">Delete all conversations?</h3>
            <p className="text-xs text-slate-400 mb-5">This will permanently delete all {conversations.length} conversation{conversations.length !== 1 ? "s" : ""} and their messages. This action cannot be undone.</p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setDeleteAllConfirm(false)} className="px-4 py-2 rounded-lg bg-slate-800 border border-slate-700 text-xs font-bold text-slate-300 hover:bg-slate-700 transition-colors">Cancel</button>
              <button onClick={deleteAllConversations} className="px-4 py-2 rounded-lg bg-red-600 text-xs font-bold text-white hover:bg-red-500 transition-colors">Delete All</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default AIChat;
