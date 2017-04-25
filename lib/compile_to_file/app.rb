require "fileutils"

module CompileToFile
  class App

    def initialize
      @files = []
      @skip_requires = []
      yield self if block_given?
    end

    def skip_requires_for(require_path)
      @skip_requires << require_path
    end

    def shebang
      "#!/usr/bin/env ruby\n"
    end

    def add_lib_files(*lib_files)
      lib_files = lib_files.flatten
      lib_files.each do |rel_path|
        add_file(File.join("lib", "#{rel_path}.rb"))
      end
    end

    def exe_file=(path)
      add_file(path)
    end

    def add_file(path)
      @files << SourceFile.new(path, @skip_requires)
    end

    def file(path)
      @files.find { |f| f.path == path }
    end

    def compile_as(output_file)
      FileUtils.mkdir_p(File.dirname(output_file))
      File.open(output_file, "w+") do |compiled|

        compiled << shebang

        @files.each do |source_file|
          compiled << source_file.processed_source

        end
      end
      File.chmod(0755, output_file)
      puts("compiled application to #{output_file}")
    end
  end
end

