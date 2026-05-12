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
      <head />
      <body>{children}</body>
    </html>
  );
}
