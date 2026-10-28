"use client";

import { useState } from "react";
import Link from "next/link";

import { Shield, Menu, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SignInButton, SignUpButton, Show } from "@clerk/nextjs";

export function Header() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-[#0B0F19]/80 backdrop-blur-md px-6 py-3.5">
      <div className="mx-auto flex max-w-7xl items-center justify-between">
        <Link href="/" className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500 to-blue-700 shadow-md shadow-sky-950/50">
            <Shield className="h-5 w-5 text-white fill-white/20" />
          </div>
          <div>
            <span className="font-bold text-white tracking-wide">AI</span>
            <span className="text-xs text-sky-400 block font-medium -mt-1">
              {process.env.NEXT_PUBLIC_APP_NAME}
            </span>
          </div>
        </Link>

        {/* Desktop Nav Links */}
        <nav className="hidden md:flex items-center gap-8 text-xs font-medium text-slate-300">
          <a href="#features" className="hover:text-sky-400 transition-colors">
            Features
          </a>
          <a href="#benefits" className="hover:text-sky-400 transition-colors">
            Benefits
          </a>
          <a href="#use-cases" className="hover:text-sky-400 transition-colors">
            Use Cases
          </a>
          <a
            href="#testimonials"
            className="hover:text-sky-400 transition-colors"
          >
            Testimonials
          </a>
          <a href="#pricing" className="hover:text-sky-400 transition-colors">
            Pricing
          </a>
        </nav>

        {/* Auth CTA Buttons */}
        <div className="hidden md:flex items-center gap-3">
          <Show when="signed-out">
            <SignInButton mode="modal">
              <button className="px-4 py-2 text-sm font-medium bg-gray-800 text-gray-200 hover:bg-gray-700 rounded-md transition-colors border border-gray-700">
                <span>Sign In</span>
              </button>
            </SignInButton>
            <SignUpButton mode="modal">
              <button className="px-4 py-2 text-sm font-medium bg-purple-600 text-white hover:bg-purple-500 rounded-md transition-colors shadow-sm">
                <span>Sign Up</span>
              </button>
            </SignUpButton>
          </Show>

          <Show when="signed-in">
            <button className="px-4 py-2 text-sm font-medium bg-purple-600 text-white hover:bg-purple-500 rounded-md transition-colors shadow-sm">
              <Link href="/dashboard">Go to Dashboard</Link>
            </button>
          </Show>
        </div>

        {/* Mobile Menu Toggle */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="md:hidden text-slate-400 hover:text-white"
        >
          {mobileMenuOpen ? (
            <X className="h-6 w-6" />
          ) : (
            <Menu className="h-6 w-6" />
          )}
        </button>
      </div>

      {/* Mobile Navigation Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden mt-4 pt-4 border-t border-slate-800 flex flex-col gap-4 text-sm font-medium">
          <a
            href="#features"
            onClick={() => setMobileMenuOpen(false)}
            className="text-slate-300 hover:text-sky-400"
          >
            Features
          </a>
          <a
            href="#benefits"
            onClick={() => setMobileMenuOpen(false)}
            className="text-slate-300 hover:text-sky-400"
          >
            Benefits
          </a>
          <a
            href="#use-cases"
            onClick={() => setMobileMenuOpen(false)}
            className="text-slate-300 hover:text-sky-400"
          >
            Use Cases
          </a>
          <a
            href="#testimonials"
            onClick={() => setMobileMenuOpen(false)}
            className="text-slate-300 hover:text-sky-400"
          >
            Testimonials
          </a>
          <a
            href="#pricing"
            onClick={() => setMobileMenuOpen(false)}
            className="text-slate-300 hover:text-sky-400"
          >
            Pricing
          </a>
          <div className="flex flex-col gap-2 pt-2 border-t border-slate-800/60">
            <Show when="signed-out">
              <SignInButton mode="modal">
                <Button
                  variant="ghost"
                  asChild
                  className="justify-start text-xs text-slate-300"
                >
                  <span>Sign In</span>
                </Button>
              </SignInButton>

              <SignUpButton mode="modal">
                <Button asChild className="bg-sky-600 text-xs text-white">
                  <span>Get Started</span>
                </Button>
              </SignUpButton>
            </Show>

            <Show when="signed-in">
              <Button asChild className="bg-sky-600 text-xs text-white">
                <Link href="/dashboard">Go to Dashboard</Link>
              </Button>
            </Show>
          </div>
        </div>
      )}
    </header>
  );
}
