$filter = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query,QueryLanguage,EventNamespace
$consumer = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Select-Object Name,CommandLineTemplate,RunInteractively
$binding = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter,Consumer
[pscustomobject]@{ filters=$filter; commandLineConsumers=$consumer; bindings=$binding }
