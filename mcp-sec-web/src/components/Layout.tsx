import { ReactNode } from "react";
import { Link } from "react-router-dom";

interface LayoutProps {
  children: ReactNode;
}

export const Layout = ({ children }: LayoutProps) => {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-primary/10 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
            <img 
              src="/driftcop-48.png" 
              alt="MCP-Drift-Cop Logo" 
              className="h-8 w-8 object-contain"
              onError={(e) => {
                // Fallback if logo doesn't exist
                e.currentTarget.src = "/driftcop.png";
              }}
            />
            <span className="text-xl font-bold bg-gradient-primary bg-clip-text text-transparent">
              Drift Cop
            </span>
          </Link>
          
          <nav className="flex items-center gap-4">
            <Link 
              to="/" 
              className="text-sm font-medium text-muted-foreground hover:text-primary transition-colors"
            >
              Dashboard
            </Link>
            <a 
              href="https://github.com/yourusername/mcp-drift-cop" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-sm font-medium text-muted-foreground hover:text-primary transition-colors"
            >
              GitHub
            </a>
          </nav>
        </div>
      </header>
      
      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {children}
      </main>
    </div>
  );
};