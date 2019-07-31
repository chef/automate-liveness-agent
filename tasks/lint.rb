# frozen_string_literal: true

desc "Run all lint checks"
task lint: "lint:check"

namespace :lint do
  desc "Lint liveness agent with chefstyle"
  task :chefstyle do
    sh "chefstyle -c .chefstyle.yml"
  end

  desc "Auto-correct liveness agent with chefstyle"
  task :chefstyle_autocorrect do
    sh "chefstyle -a -c .chefstyle.yml"
  end

  desc "Lint liveness agent recipe with cookstyle"
  task :cookstyle do
    sh "cookstyle -c .cookstyle.yml"
  end

  desc "Auto-correct liveness agent recipe with cookstyle"
  task :cookstyle_autocorrect do
    sh "cookstyle -a -c .cookstyle.yml"
  end

  desc "Run all lint checks"
  task check: %i{cookstyle chefstyle}

  desc "Autocorrect all lint issues"
  task auto: %i{cookstyle_autocorrect chefstyle_autocorrect}
end
