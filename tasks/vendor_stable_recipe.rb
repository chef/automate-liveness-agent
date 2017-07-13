require "net/http"
require "json"

def http_get(uri)
  @uri = uri

  5.times do
    uri = URI(@uri)
    req = Net::HTTP::Get.new(uri)
    res = Net::HTTP.start( uri.host, uri.port, use_ssl: uri.scheme == "https") do |http|
      http.request(req)
    end

    case res
    when Net::HTTPSuccess
      return res
    when Net::HTTPRedirection
      @uri = res["location"]
    else
      res.error!
    end
  end
end

desc "Vendor latest stable recipe"
task :vendor_stable_recipe do
  res = http_get("https://api.github.com/repos/chef/automate-liveness-agent/releases/latest")

  url = JSON.parse(res.body)["assets"].find do |a|
    a["name"] == "automate-liveness-recipe.rb"
  end["browser_download_url"]

  File.open("./test/cookbooks/liveness-agent-test/recipes/stable-compiled-recipe.rb", "w+") do |f|
    f.write(http_get(url).body)
  end
end
