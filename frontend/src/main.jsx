import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "./index.css";

import App from "./App.jsx";

import { SettingsProvider } from "./context/SettingsContext";

// NOTE: LiveSOCProvider is intentionally mounted inside MainLayout (the
// authenticated shell), not here. Mounting it at the app root made the login
// page fire unauthenticated API requests (/analytics/dashboard, /live/events)
// whose late 401 responses raced the login flow and wiped freshly stored JWT
// tokens — causing an immediate "logout" right after a successful sign-in.

createRoot(document.getElementById("root")).render(

    <StrictMode>

        <SettingsProvider>

            <App />

        </SettingsProvider>

    </StrictMode>

);
