import type { Metadata } from "next";
import "./globals.css";
import SiteNav from "./components/SiteNav";
import SiteFooter from "./components/SiteFooter";
import SocChat from "./components/SocChat";

export const metadata: Metadata = {
  title: "CyberSec Platform",
  description: "AI-Powered Threat Detection & Response Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="h-full">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-full bg-black text-white" suppressHydrationWarning>
        <SiteNav />
        {children}
        <SiteFooter />
        <SocChat />
      </body>
    </html>
  );
}
