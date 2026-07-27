import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ShieldScore",
  description: "ShieldScore repository security and compliance auditing.",
  authors: [{ name: "Lakshya" }],
  openGraph: {
    title: "ShieldScore",
    description: "Repository security and compliance auditing.",
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "ShieldScore security audit dashboard" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "ShieldScore",
    description: "Repository security and compliance auditing.",
    images: ["/og.png"],
  },
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
