import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./app.css";
import "./auth-polish.css";
import "./captcha.css";
import "./login-form-width.css";
import "./login-layout.css";
import "./login-premium.css";
import "./login-radar-restore.css";
import "./login-radar.css";
import "./login-robot-svg.css";
import "./login-robot.css";
import "./login-telemetry.css";
import "./login-title-sync.css";
import "./dns-dashboard.css";

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
