function s1=combine_struct(s1,s2,option,suffix)
% S=combine_struct(s1,s2,option,suffix)
% Combine two structs. 
% s1=combine_structs(s1,s2)
%   adds contents of s2 to s1, overwriting by default
% s1=combine_structs(s1,s2,false)
%   adds contents of s2 to s1, avoid overwrite.
% s1=combine_structs(s1,s2,'data_prefix')
%   adds contents of s2 to s1, putting data_prefix on all element names.
% s1=combine_structs(s1,s2,'SUFFIX','suffix_to_append')
%   adds contents of s2 to s1, putting suffix_to_append at the end of all element names.
% s1=combine_structs(s1,s2,'combine')
%   adds contents of s2 to s1, attempting to concatenate any entry with the same name.
% 
% Written by James Cook ~ circa 2013

name_mod='';
suffix_mode=false;
overwrite=true;
if ~exist('option','var')
   option=true;
end


if ischar(option)
    if strcmp(option,'combine')
        overwrite=false;
        name_mod='';
    elseif strcmp(option,'SUFFIX')
        suffix_mode=true;
        name_mod=suffix;
    else
        overwrite=true;
        name_mod=option;
        if nargin==4
            error('Unexpected trailing arg! did you misspell a key word?');
        end
    end
elseif option
    overwrite=true;
else
    overwrite=false;
end 




f = fieldnames(s2);
for i = 1:length(f)
    %new fieldname in s1
    if ~suffix_mode
        fname=[name_mod f{i} ]; 
    else
        fname=[f{i} name_mod ];
    end
    if overwrite==true
        s1.(fname) = s2.(f{i});
    elseif ~isfield(s1,fname)
        s1.(fname) = s2.(f{i});
    elseif strcmp(option,'combine')
        % try to cat things....
        if iscell(s1.(fname)) && iscell(s2.(f{i})) 
            s1.(fname) = [s1.(fname) s2.(f{i})];
        else
        try
            s1.(fname)=cat(s1.(fname),s2.(f{i}));
        catch err
            error('field %s of s1 existed and could not cat with field of s2',fname);
        end
        end
    else
        % not supposed to overwrite, and field exists
    end
    
end
