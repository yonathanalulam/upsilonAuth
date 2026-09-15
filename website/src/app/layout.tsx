import type { Metadata } from "next";
import { Geist_Mono, Manrope } from "next/font/google";
import "./globals.css";

const manrope = Manrope({
  variable: "--font-manrope",
  subsets: ["latin"],
  display: "swap",
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "UpsilonAuth",
  description:
    "Temporary, delegated authority for machine workloads.",
  metadataBase: new URL("https://github.com/yonathanalulam/upsilonAuth"),
  icons: {
    icon: "/upsilonauth-logo.svg",
    shortcut: "/upsilonauth-logo.svg",
    apple: "/upsilonauth-logo.svg",
  },
  openGraph: {
    title: "UpsilonAuth",
    description:
      "Temporary, delegated authority for machine workloads.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `try{const t=localStorage.getItem("upsilonauth-theme")||(matchMedia("(prefers-color-scheme:light)").matches?"light":"dark");document.documentElement.dataset.theme=t}catch{}`,
          }}
        />
      </head>
      <body className={`${manrope.variable} ${geistMono.variable}`}>
        {children}
      </body>
    </html>
  );
}
