dyn-livedns-gandi
=================

*Update your Gandi LiveDNS records with your current IP address*

Usage
-----

To use this tool, you must create a config file with the following content:

```ini
[main]
api_key = XXXXXXXXXXXX
domain = my-domain.tld
records = foo,bar
```

* `api_key` is your Gandi's API key
* `domain` is the domain associated to the zone you want to update (you can also use the key `zone` with the uuid of the zone as value).
* `records` is the list of the records you want to update.

Then, you can run the following command: `dyn-livedns-gandi --config [YOUR-FILE]`
