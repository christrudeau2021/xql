import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "XQL Shield — Cortex XDR Query Translator",
  description:
    "Translate natural language threat hunting into XQL queries for Palo Alto Networks Cortex XDR / XSIAM",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
        <meta name="theme-color" content="#020608" />
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
      </head>
      <body>{children}</body>
    </html>
  );
}
