require "compile_to_file"

desc "Compile the application to a single file for deployment"
task :compile do
  CompileToFile::App.new do |app|

    app.skip_requires_for("automate_liveness_agent")

    app.add_lib_files(%w{
      automate_liveness_agent/vendor/mixlib-authentication/lib/mixlib/authentication/null_logger
      automate_liveness_agent/vendor/mixlib-authentication/lib/mixlib/authentication
      automate_liveness_agent/vendor/mixlib-authentication/lib/mixlib/authentication/digester
      automate_liveness_agent/vendor/mixlib-authentication/lib/mixlib/authentication/signedheaderauth
      automate_liveness_agent/version
      automate_liveness_agent/config
      automate_liveness_agent/api_client
      automate_liveness_agent/liveness_update_sender
      automate_liveness_agent/main
    })
    app.exe_file = "bin/automate-liveness-agent"

    app.file("lib/automate_liveness_agent/vendor/mixlib-authentication/lib/mixlib/authentication.rb").
      swap.replace(<<-THIS).with(<<-THAT)
    begin
      require "mixlib/log"
      Mixlib::Authentication::Log.extend(Mixlib::Log)
    rescue LoadError
      require "automate_liveness_agent/vendor/mixlib-authentication/lib/mixlib/authentication/null_logger"
      Mixlib::Authentication::Log.extend(Mixlib::Authentication::NullLogger)
    end
THIS
    Mixlib::Authentication::Log.extend(Mixlib::Authentication::NullLogger)
THAT
  end.compile_as("build/automate-liveness-agent")

end
