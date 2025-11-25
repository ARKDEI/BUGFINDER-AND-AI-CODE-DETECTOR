fetch("/api/data")
  .then(r => r.json()) // promise_no_catch
  .then(data => console.log(data));
