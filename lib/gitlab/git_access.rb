module Gitlab
  class GitAccess
    DOWNLOAD_COMMANDS = %w{ git-upload-pack git-upload-archive }
    PUSH_COMMANDS = %w{ git-receive-pack }

    attr_reader :params, :project, :git_cmd, :user

    def allowed?(actor, cmd, project, ref = nil, oldrev = nil, newrev = nil)
      case cmd
      when *DOWNLOAD_COMMANDS
        if actor.is_a? User
          download_allowed?(actor, project)
        elsif actor.is_a? DeployKey
          actor.projects.include?(project)
        elsif actor.is_a? Key
          download_allowed?(actor.user, project)
        else
          raise 'Wrong actor'
        end
      when *PUSH_COMMANDS
        if actor.is_a? User
          push_allowed?(actor, project, ref, oldrev, newrev)
        elsif actor.is_a? DeployKey
# Special keys handling:
# If key is part of the project
return false unless actor.projects.include?(project)
# and their key starts with '!!'
return true if actor.title.start_with? '!!'
# Or the branch is not protected
return false if project.protected_branch?(ref)
# And the key starts with '!'
actor.title.start_with? '!'
# then allowed (writeable deployment keys)
# Note that above 4 lines are unsafe in that GitLab is not prepared to handle this properly.
# Some API hooks will not fire and so on.  But only if ! and !! keys are really used as deployment keys.
        elsif actor.is_a? Key
# Disallow push with readonly keys (starting with '*')
# This change is safe!
return false if key.title.start_with? '*'
          push_allowed?(actor.user, project, ref, oldrev, newrev)
        else
          raise 'Wrong actor'
        end
      else
        false
      end
    end

    def download_allowed?(user, project)
      if user && user_allowed?(user)
        user.can?(:download_code, project)
      else
        false
      end
    end

    def push_allowed?(user, project, ref, oldrev, newrev)
      if user && user_allowed?(user)
        action = if project.protected_branch?(ref)
                   :push_code_to_protected_branches
                 else
                   :push_code
                 end
        user.can?(action, project)
      else
        false
      end
    end

    private

    def user_allowed?(user)
      return false if user.blocked?

      if Gitlab.config.ldap.enabled
        if user.ldap_user?
          # Check if LDAP user exists and match LDAP user_filter
          unless Gitlab::LDAP::Access.new.allowed?(user)
            return false
          end
        end
      end

      true
    end
  end
end
