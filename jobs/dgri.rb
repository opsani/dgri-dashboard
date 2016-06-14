# :first_in sets how long it takes before the job is first run. In this case, it is run immediately

require "date"
require 'json'
require 'net/http'
require 'uri'

class Dgri

    def initialize(apiUrl, username, password)
        @url      = apiUrl
        @username = username
        @password = password

        @cve_info_cache = {}
    end

    def api_request(url, parse=true)
        req = Net::HTTP::Get.new(url)
        req.basic_auth @username, @password
        res = Net::HTTP.start(url.hostname, url.port,
          :use_ssl => url.scheme == 'https',
          :verify_mode => OpenSSL::SSL::VERIFY_NONE) {|http|
            http.request(req)
        }
        if parse
            return JSON[res.body]
        else
            return res.body
        end
    end

    def get_affected_sys(cve)
        url = URI.parse("#{@url}/systems?vuln.id=#{cve}&view=count")
        return api_request url, false
    end

    def get_vulns()
      url = URI.parse("#{@url}/vulns")
      vulns = api_request url

      data = {
        sev10: 0,
        sev9: 0,
        sev8: 0,
        sev5: 0,
        all: 0,
      }

      for idx in 0 ... vulns.size
          vuln = vulns[idx]
          sev = vuln["severity"].to_f

          data[:all] += 1

          if sev >=5
            data[:sev5] += 1
          end

          if sev >=8
            data[:sev8] += 1
          end

          if sev >=9
            data[:sev9] += 1
          end

          if sev == 10
            data[:sev10] += 1
          end

      end

      return {
        all: data[:all],
        data: vulns,
        crit: data[:sev10],
        items: [
            {
                "label" => "Critical (Severity 10)",
                "value" => data[:sev10]
            },
            {
                "label" => "Severity 9+",
                "value" => data[:sev9]
            },
            {
                "label" => "Severity 8+",
                "value" => data[:sev8]
            },
            {
                "label" => "Severity 5+",
                "value" => data[:sev5]
            },
            {
                "label" => "All",
                "value" => data[:all]
            },
          ]
      }

    end

    def get_active_sys()

        day_active = 3
        if ENV["DGRI_DAYS_ACTIVE"] != nil and ENV["DGRI_DAYS_ACTIVE"] != "None"
            day_active = ENV["DGRI_DAYS_ACTIVE"].to_i
        end

        days_last  = 7

        date_last_signal  = DateTime.now - day_active
        date_last_created = DateTime.now - days_last
        date_active_last  = DateTime.now - (days_last + day_active)
        url = URI.parse("#{@url}/systems?view=normal&system.last_signal=min:#{date_last_signal}")
        current = api_request url

        url = URI.parse("#{@url}/systems?view=count&system.created=max:#{date_last_created}&system.last_signal=min:#{date_active_last}")
        last = api_request url, false


        os = {}
        # Get OS breakdown from config id
        for system in current
            config_id = system["config_id"] || "unknown-"
            os_name, os_ver, _ = config_id.split('-')
            os_full_name = "#{os_name} #{os_ver}"

            if not os.key?(os_name)
                os[os_name] = {}
            end

            if os[os_name].key?(os_full_name)
                os[os_name][os_full_name] += 1
            else
                os[os_name][os_full_name] = 1
            end
        end

        by_os = [
          ['OS'           ,   'Parent',   'Systems' ],
          ['Systems by OS',   nil     ,   0         ],
        ]

        for os_name in os.keys
            by_os.push([os_name.capitalize, 'Systems by OS',  0 ])
            for os_full_name in os[os_name].keys
                by_os.push([
                  os_full_name.capitalize,
                  os_name.capitalize,
                  os[os_name][os_full_name]]
                )
            end
        end

        return { current: current.size, last: last, by_os: by_os }
    end

    def get_vuln_systems(fixable=false, severity=0)
      url_str = "#{@url}/systems?vuln.severity=min:#{severity}&view=count"

      if fixable
        url_str += "&vuln.fixes=full"
      end

      url = URI.parse(url_str)
      return api_request url, false

    end

    def get_fixable_vulns(since=nil, severity=nil)
      url_str = "#{@url}/vulns?vuln.fixes=full&view=count"

      if since != nil
        changed = DateTime.now - since
        url_str += "&vuln.changed=min:#{changed}"
      end

      if severity != nil
        url_str += "&vuln.severity=min:#{severity}"
      end

      url = URI.parse(url_str)
      return api_request url, false
    end

    def get_vuln_info(cve)

      if @cve_info_cache.key?(cve)
        return @cve_info_cache[cve]
      end

      url_str = "#{@url}/vulns/#{cve}"
      url = URI.parse(url_str)
      resp = api_request url
      desc = resp["description"]
      @cve_info_cache[cve] = desc
      return desc
    end

    def get_top_vulns(data=nil, since=nil, count=5)
        since ||= DateTime.now - 7
        url = URI.parse("#{@url}/vulns?vuln.changed=min:#{since}")
        data ||= api_request url

        sorted = data.sort {
            |a, b|
            [a['severity'].to_f] <=>
            [b['severity'].to_f]
        }.reverse

        data_cutoff = []
        cutoff_severity = 10
        for idx in 0 ... sorted.size
            if idx == count - 1
                cutoff_severity = sorted[idx]['severity'].to_f
            elsif idx >= count
                if sorted[idx]['severity'].to_f < cutoff_severity
                    break
                end
            end

            data_cutoff[idx] = sorted[idx]
            data_cutoff[idx]["n_affected"] = get_affected_sys(sorted[idx]["id"])
        end

        data_sorted = data_cutoff.sort {
            |a, b|
            [a['severity'].to_f, a["n_affected"].to_i] <=>
            [b['severity'].to_f, b["n_affected"].to_i]
        }.reverse

        ret=[]
        for idx in 0 ... data_sorted.size
            if idx >= count
                break
            end

            cve_id = data_sorted[idx]['id']
            desc = get_vuln_info(cve_id)

            ret[idx] = {
                label: "<a target='_blank' title='#{desc}' href='https://web.nvd.nist.gov/view/vuln/detail?vulnId=#{cve_id}'>#{cve_id}</a>",
                value: "#{data_sorted[idx]['severity']}  x#{data_sorted[idx]['n_affected']}"
            }
        end

        return { items: ret, total: data.size }
    end

    def get_stats()

      vulns = get_vulns
      active_sys = get_active_sys

      top_new_vulns = get_top_vulns
      top_new_vulns[:items].push({
          label: "Total New Vulns",
          value: top_new_vulns[:total]})

      top_vulns = get_top_vulns(vulns[:data], "0", 6)

      stats = {
        active_systems: {
          current: active_sys[:current],
          last: active_sys[:last]
        } ,
        os_breakdown: { items: active_sys[:by_os] },
        top_new_vulns: { items: top_new_vulns[:items]},
        top_vulns: { items: top_vulns[:items]},
        n_vulns: { current: vulns[:all] },
        vulns_breakdown: { items: vulns[:items] },
        vuln_fixable: {
          big: get_fixable_vulns(nil, 10),
          small: get_fixable_vulns},
        critical_vulns: {
          big: vulns[:crit],
          small: get_vuln_systems(false, 10)},

        vulnerable_systems: {
          big:  get_vuln_systems(true),
          small: get_vuln_systems(false)
        },

      }

      return stats
    end

end


INTERVAL      = ENV["INTERVAL"]      || 30
DGRI_URL      = ENV["DGRI_URL"]      || "https://api.datagridsys.com/api/v3"
DGRI_USERNAME = ENV["DGRI_USERNAME"]
DGRI_PASSWORD = ENV["DGRI_PASSWORD"]

SCHEDULER.every "#{INTERVAL}m", :first_in => 0 do |job|

    # Create an instance of our helper class
    dgri = Dgri.new DGRI_URL, DGRI_USERNAME, DGRI_PASSWORD


    start = Time.now
    stats = dgri.get_stats

    STDERR.puts Time.now - start
    STDERR.puts stats

    stats.keys.each do |key|
      send_event(key, stats[key])
    end


end
