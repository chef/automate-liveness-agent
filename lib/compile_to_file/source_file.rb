module CompileToFile
  class SourceFile

    attr_reader :path
    attr_reader :swaps
    attr_reader :skip_requires

    def initialize(path, skip_requires)
      @path = path
      @swaps = []
      @skip_requires = skip_requires
      yield self if block_given?
    end

    def swap
      new_swap = CodeSwap.new
      swaps << new_swap
      new_swap
    end

    def processed_source
      processed = ""

      File.open(path, "r") do |code_file|

        # Annotate with source file path for debug help
        processed << "## #{path} ##\n"

        code = code_file.read

        swaps.each { |s| s.apply_to!(code, path) }

        # Strip comments and shebangs
        code.gsub!(/^\s*#.*\n/, "")
        # Strip empty lines
        code.gsub!(/^\n/, "")
        # Remove internal requires
        skip_requires.each do |require_path|
          code.gsub!(/^require \"#{require_path}.*\n/, "")
        end

        processed << code
      end
    end

  end
end

