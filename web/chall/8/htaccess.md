# `.htaccess` File Explained

## What is `.htaccess`?

`.htaccess` (Hypertext Access) is a **configuration file** used by Apache web servers. It allows you to override server settings on a **per-directory basis** without needing access to the main server configuration.

## Basic Structure

```apache
DirectiveName Value
# This is a comment
```

## Common Uses

### 1. URL Rewriting (Most Famous)
```apache
RewriteEngine On
RewriteRule ^blog/(.*)$ blog.php?slug=$1
```

### 2. Custom Error Pages
```apache
ErrorDocument 404 /errors/not-found.html
ErrorDocument 500 /errors/server-error.html
```

### 3. Password Protection
```apache
AuthType Basic
AuthName "Restricted Area"
AuthUserFile /path/to/.htpasswd
Require valid-user
```

### 4. MIME Type Configuration
```apache
AddType application/x-httpd-php .jpg .html .txt
AddType application/pdf .pdf
```

## The Vulnerability We Exploited

### Malicious `.htaccess`:
```apache
AddType application/x-httpd-php .jpg .jpeg .png .gif
```

**What this does:**
- Tells Apache: "Treat files with .jpg, .jpeg, .png, .gif extensions as PHP files"
- Normally: `.jpg` → served as image
- With this: `.jpg` → executed as PHP code

### How Apache Processes This:

1. **Request comes in**: `GET /images/shell.jpg`
2. **Apache checks**: File exists → what type is it?
3. **Sees `.htaccess`**: "Ah, .jpg files should be processed as PHP!"
4. **Executes**: Runs the PHP code in `shell.jpg` instead of serving it as image

## Other Dangerous `.htaccess` Configurations

### Execute All Files as PHP:
```apache
<FilesMatch ".*">
    SetHandler application/x-httpd-php
</FilesMatch>
```

### Specific File Execution:
```apache
<Files "backdoor.jpg">
    SetHandler application/x-httpd-php
</Files>
```

### Force PHP Execution with Headers:
```apache
<FilesMatch "\.(jpg|png)$">
    ForceType application/x-httpd-php
</FilesMatch>
```

## Security Implications

### Why This is Dangerous:
1. **Bypasses Upload Filters**: Upload "image.jpg" that contains PHP code
2. **Persistent Access**: Configuration remains until file is deleted
3. **Hard to Detect**: Looks like normal server configuration

### Attack Scenarios:
- Upload `.htaccess` + malicious file with image extension
- Gain code execution on the server
- Read sensitive files, execute commands, create backdoors

## Prevention

### Server-Level Protection:
```apache
# In main httpd.conf - disable .htaccess entirely
<Directory /var/www/uploads>
    AllowOverride None
</Directory>
```

### Restricted Overrides:
```apache
# Only allow safe overrides
AllowOverride AuthConfig Indexes
# BUT NOT: FileInfo (which includes AddType)
```

### Upload Directory Restrictions:
```apache
<Directory /var/www/uploads>
    # Prevent PHP execution entirely
    php_flag engine off
    # Only serve static files
    RemoveHandler .php .php5 .phtml
</Directory>
```

## Real-World Impact

**If an attacker can upload `.htaccess`:**
- ✅ Execute any file type as PHP
- ✅ Rewrite URLs to hide malicious content  
- ✅ Password protect their backdoors
- ✅ Set custom error pages to hide attacks
- ✅ Block IP addresses (including admins)

## Key Takeaway

The `.htaccess` file is powerful because it gives **directory-level control** over Apache's behavior. When combined with file upload functionality, it becomes a critical security vulnerability if not properly restricted.

This is why secure applications:
- Store uploaded files outside web root
- Disable `.htaccess` in upload directories
- Use proper file type validation (MIME types, not just extensions)
- Implement strict file permission controls