# Automate Liveness Agent

Automate liveness agent sends keepalive messages to Chef Automate, which
prevents nodes that are up but not frequently running Chef Client from
appearing as "missing" in the Automate UI.

For more info about Chef Automate, see [https://www.chef.io/automate/](https://www.chef.io/automate/).

## Installation

Automate liveness agent is designed to be installed via Chef's "Required
Recipe" feature, which is in development. Check back later for full
instructions.

## Usage

Usage instructions will be made available once this software is
released.

### Configuration

The config file is a JSON formatted file like this:

```json
{
  "chef_server_url": "https://chef.example/organizations/org-name",
  "client_key_path":  "/etc/chef/client.pem",
  "client_name":      "example-node-name",
  "unprivileged_uid": 100,
  "unprivileged_gid": 200
}
```

### Environment Variables

#### `DEBUG`

Setting `DEBUG=1` will enable logging of HTTP request data.

#### `INTERVAL`

By default, the liveness agent will send an update every 30 minutes.
Setting the `INTERVAL` variable will configure the agent to send an
update to the specified value (in seconds).

#### `RUBYOPT`

Pending some in-progress improvements, this application is designed to
run with rubygems disabled. This can be done by setting `RUBYOPT` like
so:

```
RUBYOPT="--disable-gems"
```

## Development

This project is developed as a typical ruby app with bundler and rspec.

To install deps:

```
bundle install
```

To run tests:

```
bundle exec rspec
```

## Contributing

Bug reports should be filed with your support representitive.

