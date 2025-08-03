# Logo Setup Instructions

The MCP-Drift-Cop logos are already set up and located in the `logos/` directory:

## Available Logos
- `logos/driftcop16X16.png` - Small icon size (16x16px)
- `logos/driftcop48x48.png` - Header/navigation size (48x48px)
- `logos/driftcop400x400.png` - Large size for README and social media (400x400px)

## Current Usage
1. **README.md**: Uses `logos/driftcop400x400.png` (displayed at 200x200px)
2. **Web Application**: 
   - Header: `/public/driftcop-48.png` (48x48px optimized version)
   - Main logo: `/public/driftcop.png` (400x400px for social media)
   - Favicon: `/public/favicon.ico` (16x16px version)

## Logo Requirements
- Format: PNG (transparent background recommended)
- Recommended size: 512x512px or larger
- The logo will be automatically resized in the application
- Optimize the file size for web use (use tools like TinyPNG)

## Where the Logo Appears
1. **README.md**: At the top of the file (200x200px)
2. **Web Application Header**: In the navigation bar (32x32px)
3. **Browser Favicon**: As the browser tab icon
4. **Social Media**: When sharing links (Open Graph and Twitter cards)

## Fallback
If the logo file is missing, the web application will fall back to `/placeholder.svg` which already exists in the public directory.