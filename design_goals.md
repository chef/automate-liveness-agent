# Design Goals

As of the creation of this project in April 2017, we made the following
technical choices based on our product priorities:

### Ruby

It's written in ruby because we've already ported ruby to all of the
platforms we support. Given our other requirements, rust would've
otherwise been a good alternative.

### Minimize RAM Use

Despite our choice of ruby, we want to keep the smallest footprint we
can. Some folks do not run Chef Client daemonized because of the
resources required to run Chef; we want this app to be small enough for
that to not be a problem.

To achieve that:
* minimize code size: ruby code becomes ruby objects. Less code means
  fewer objects.
* avoid all dependency resolution: rubygems is ruby code, which means it
  has a memory cost. Runtime dependency resolution also has other
  issues, which you usually would mitigate with bundler, which is yet
  more code you have to run.
* minimize feature set: fewer features means less code

As a result, it may be difficult to add significant new features,
especially if implementing a feature would require new libraries.

### Ship as a Single File

Shipping as a single file makes distribution a lot easier given the
mechanism we are using for distribution (Chef required recipe feature).

A nice side effect of this is that we don't have to hit the filesystem
very much on boot, which is especially costly on windows.

The downside of this is that we have to maintain code that compiles the
app down to a single file. To make that work, we have to munge some of
the code (especially `require` statements). There are a lot of valid
ruby constructions that would break our naive code editing, so we have
to use only a sane subset of ruby.

